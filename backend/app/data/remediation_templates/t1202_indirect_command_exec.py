"""
T1202 - Indirect Command Execution

Adversaries abuse Windows utilities (forfiles, pcalua.exe, WSL, scriptrunner.exe, ssh.exe)
to execute commands whilst bypassing security controls that restrict command-line interpreters.
Used by Lazarus Group and RedCurl.
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
    technique_id="T1202",
    technique_name="Indirect Command Execution",
    tactic_ids=["TA0005"],
    mitre_url="https://attack.mitre.org/techniques/T1202/",
    threat_context=ThreatContext(
        description=(
            "Adversaries abuse Windows system utilities to execute commands whilst bypassing "
            "security restrictions that limit command-line interpreter usage. This defence evasion "
            "tactic exploits built-in Windows tools including forfiles.exe, pcalua.exe (Program "
            "Compatibility Assistant), wsl.exe (Windows Subsystem for Linux), scriptrunner.exe, "
            "and ssh.exe to circumvent controls such as Group Policy restrictions on cmd.exe. "
            "On cloud Windows instances, attackers leverage these utilities to execute arbitrary "
            "code whilst subverting detections and mitigation controls."
        ),
        attacker_goal="Execute commands whilst bypassing cmd.exe restrictions and security controls",
        why_technique=[
            "Circumvents Group Policy restrictions targeting cmd.exe",
            "Evades security controls that monitor standard command interpreters",
            "Uses legitimate Windows binaries to avoid suspicion",
            "Enables execution of PowerShell, cmd, and other interpreters indirectly",
            "Can establish persistence through scheduled tasks and registry modifications",
            "SSH configuration file abuse enables command execution on connection",
            "WSL provides alternative Linux environment for executing malicious code",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="moderate",
        trend="increasing",
        severity_score=6,
        severity_reasoning=(
            "Indirect Command Execution is a defence evasion technique that allows attackers to "
            "bypass security controls and execute arbitrary commands on Windows cloud instances. "
            "Whilst the technique itself doesn't grant privilege escalation, it enables execution "
            "of secondary payloads (PowerShell, malware, credential dumpers) whilst evading "
            "detections. The use of legitimate Windows utilities makes detection challenging, as "
            "these tools have valid administrative use cases."
        ),
        business_impact=[
            "Bypass of application control and command-line restrictions",
            "Execution of malicious PowerShell scripts and binaries",
            "Evasion of endpoint detection and response (EDR) solutions",
            "Persistence establishment through scheduled tasks",
            "Lateral movement to other Windows instances",
            "Data exfiltration via spawned processes",
            "Deployment of ransomware and remote access trojans",
        ],
        typical_attack_phase="defense_evasion",
        often_precedes=["T1059.001", "T1059.003", "T1003", "T1053"],
        often_follows=["T1078.004", "T1190", "T1133", "T1566"],
    ),
    detection_strategies=[
        # Strategy 1: Monitor Indirect Execution Utilities
        DetectionStrategy(
            strategy_id="t1202-aws-indirect-utils",
            name="AWS: Monitor Indirect Command Execution Utilities",
            description=(
                "Monitor CloudWatch Logs for execution of indirect command execution utilities "
                "(forfiles.exe, pcalua.exe, wsl.exe, scriptrunner.exe, ssh.exe) followed by "
                "spawned child processes such as PowerShell, cmd.exe, or suspicious binaries."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, EventID, Computer, ParentProcessName, NewProcessName, CommandLine
| filter EventID = 4688
| filter ParentProcessName like /forfiles[.]exe|pcalua[.]exe|wsl[.]exe|scriptrunner[.]exe|ssh[.]exe/i
| filter NewProcessName like /powershell[.]exe|cmd[.]exe|msiexec[.]exe|regsvr32[.]exe|wscript[.]exe|cscript[.]exe/i
| stats count() as executions by Computer, ParentProcessName, NewProcessName, bin(10m)
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect indirect command execution utilities on Windows instances

Parameters:
  CloudWatchLogGroup:
    Type: String
    Description: Log group containing Windows Security Event logs
    Default: /aws/ec2/windows/security
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # Step 1: Create SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      KmsMasterKeyId: alias/aws/sns
      DisplayName: Indirect Command Execution Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Create metric filter for indirect execution utilities
  IndirectExecFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudWatchLogGroup
      FilterPattern: '{ ($.EventID = 4688) && ($.ParentProcessName = "*forfiles.exe" || $.ParentProcessName = "*pcalua.exe" || $.ParentProcessName = "*wsl.exe" || $.ParentProcessName = "*scriptrunner.exe" || $.ParentProcessName = "*ssh.exe") && ($.NewProcessName = "*powershell.exe" || $.NewProcessName = "*cmd.exe" || $.NewProcessName = "*msiexec.exe" || $.NewProcessName = "*regsvr32.exe") }'
      MetricTransformations:
        - MetricName: IndirectCommandExecution
          MetricNamespace: Security/T1202
          MetricValue: "1"
          DefaultValue: 0

  # Step 3: Create alarm for indirect execution
  IndirectExecAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1202-IndirectCommandExecution
      AlarmDescription: Indirect command execution detected on Windows instance
      MetricName: IndirectCommandExecution
      Namespace: Security/T1202
      Statistic: Sum
      Period: 300
      Threshold: 1
      ComparisonOperator: GreaterThanOrEqualToThreshold
      EvaluationPeriods: 1
      AlarmActions:
        - !Ref AlertTopic
      TreatMissingData: notBreaching

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref AlertTopic
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: cloudwatch.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic""",
                terraform_template="""# Detect indirect command execution utilities on Windows instances

variable "cloudwatch_log_group" {
  type        = string
  description = "Log group containing Windows Security Event logs"
  default     = "/aws/ec2/windows/security"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "indirect_exec_alerts" {
  name         = "indirect-command-execution-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "Indirect Command Execution Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.indirect_exec_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for indirect execution utilities
resource "aws_cloudwatch_log_metric_filter" "indirect_exec" {
  name           = "indirect-command-execution"
  log_group_name = var.cloudwatch_log_group
  pattern        = "{ ($.EventID = 4688) && ($.ParentProcessName = \"*forfiles.exe\" || $.ParentProcessName = \"*pcalua.exe\" || $.ParentProcessName = \"*wsl.exe\" || $.ParentProcessName = \"*scriptrunner.exe\" || $.ParentProcessName = \"*ssh.exe\") && ($.NewProcessName = \"*powershell.exe\" || $.NewProcessName = \"*cmd.exe\" || $.NewProcessName = \"*msiexec.exe\" || $.NewProcessName = \"*regsvr32.exe\") }"

  metric_transformation {
    name          = "IndirectCommandExecution"
    namespace     = "Security/T1202"
    value         = "1"
    default_value = 0
  }
}

# Step 3: Create alarm for indirect execution
resource "aws_cloudwatch_metric_alarm" "indirect_exec" {
  alarm_name          = "T1202-IndirectCommandExecution"
  alarm_description   = "Indirect command execution detected on Windows instance"
  metric_name         = "IndirectCommandExecution"
  namespace           = "Security/T1202"
  statistic           = "Sum"
  period              = 300
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.indirect_exec_alerts.arn]
  treat_missing_data  = "notBreaching"
}

resource "aws_sns_topic_policy" "indirect_exec_alerts" {
  arn = aws_sns_topic.indirect_exec_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "SNS:Publish"
      Resource  = aws_sns_topic.indirect_exec_alerts.arn
    }]
  })
}""",
                alert_severity="high",
                alert_title="Indirect Command Execution Detected",
                alert_description_template=(
                    "Indirect command execution detected on {computer}. "
                    "Parent: {parent_process_name} spawned {new_process_name}. "
                    "Command: {command_line}. This may indicate defence evasion."
                ),
                investigation_steps=[
                    "Review the full command-line of the spawned process",
                    "Identify the user account that executed the indirect utility",
                    "Check if execution matches authorised administrative activity",
                    "Examine the chain: what launched the indirect utility (forfiles, pcalua, etc.)?",
                    "Review Windows Event ID 4688 for complete process creation history",
                    "Check for network connections from spawned processes",
                    "Search for SSH config file modifications in %USERPROFILE%\\.ssh\\config",
                    "Verify WSL usage patterns if wsl.exe was the parent process",
                ],
                containment_actions=[
                    "Terminate suspicious spawned processes (PowerShell, cmd.exe)",
                    "Kill the indirect execution utility process if still running",
                    "Review and enforce Group Policy restrictions on indirect utilities",
                    "Isolate the instance if compromise is confirmed",
                    "Disable WSL if not required for business operations",
                    "Audit and lock down SSH configuration files",
                    "Review application control policies to block indirect execution methods",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist authorised administrative scripts using forfiles; baseline normal WSL usage patterns",
            detection_coverage="80% - captures most indirect execution chains with common utilities",
            evasion_considerations="Attackers may use renamed utilities or alternative indirect methods not in the detection list",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1.5 hours",
            estimated_monthly_cost="$10-20 depending on log volume",
            prerequisites=[
                "CloudWatch Agent installed on Windows instances",
                "Windows Process Creation auditing enabled (Event ID 4688)",
                "Process command-line logging enabled",
            ],
        ),
        # Strategy 2: SSH Configuration File Monitoring
        DetectionStrategy(
            strategy_id="t1202-ssh-config-abuse",
            name="AWS: Monitor SSH Configuration File Modifications",
            description=(
                "Detect modifications to SSH configuration files (%USERPROFILE%\\.ssh\\config) "
                "that abuse ProxyCommand or LocalCommand options via the -o flag to execute "
                "arbitrary commands when SSH connections are established."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, @message, Computer, ProcessName, CommandLine
| filter @message like /[.]ssh.config|ProxyCommand|LocalCommand|ssh[.]exe.*-o/i
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect SSH configuration file abuse for indirect command execution

Parameters:
  SystemLogGroup:
    Type: String
    Description: Log group containing Windows system/file access logs
    Default: /aws/ec2/windows/system
  AlertEmail:
    Type: String
    Description: Email for alerts

Resources:
  # Step 1: Create SNS topic
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      KmsMasterKeyId: alias/aws/sns
      DisplayName: SSH Config Abuse Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Create metric filter for SSH config modifications
  SSHConfigFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref SystemLogGroup
      FilterPattern: '[time, computer, event, path="*\\.ssh\\\\config*" || command="*ProxyCommand*" || command="*LocalCommand*" || command="*ssh.exe*-o*"]'
      MetricTransformations:
        - MetricName: SSHConfigAbuse
          MetricNamespace: Security/T1202
          MetricValue: "1"
          DefaultValue: 0

  # Step 3: Create alarm for SSH config abuse
  SSHConfigAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1202-SSHConfigAbuse
      AlarmDescription: SSH configuration file abuse detected
      MetricName: SSHConfigAbuse
      Namespace: Security/T1202
      Statistic: Sum
      Period: 300
      Threshold: 1
      ComparisonOperator: GreaterThanOrEqualToThreshold
      EvaluationPeriods: 1
      AlarmActions:
        - !Ref AlertTopic
      TreatMissingData: notBreaching

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref AlertTopic
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: cloudwatch.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic""",
                terraform_template="""# Detect SSH configuration file abuse for indirect command execution

variable "system_log_group" {
  type        = string
  description = "Log group containing Windows system/file access logs"
  default     = "/aws/ec2/windows/system"
}

variable "alert_email" {
  type        = string
  description = "Email for alerts"
}

# Step 1: Create SNS topic
resource "aws_sns_topic" "ssh_config_alerts" {
  name         = "ssh-config-abuse-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "SSH Config Abuse Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.ssh_config_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for SSH config modifications
resource "aws_cloudwatch_log_metric_filter" "ssh_config_abuse" {
  name           = "ssh-config-abuse"
  log_group_name = var.system_log_group
  pattern        = "[time, computer, event, path=\"*\\\\.ssh\\\\\\\\config*\" || command=\"*ProxyCommand*\" || command=\"*LocalCommand*\" || command=\"*ssh.exe*-o*\"]"

  metric_transformation {
    name          = "SSHConfigAbuse"
    namespace     = "Security/T1202"
    value         = "1"
    default_value = 0
  }
}

# Step 3: Create alarm for SSH config abuse
resource "aws_cloudwatch_metric_alarm" "ssh_config_abuse" {
  alarm_name          = "T1202-SSHConfigAbuse"
  alarm_description   = "SSH configuration file abuse detected"
  metric_name         = "SSHConfigAbuse"
  namespace           = "Security/T1202"
  statistic           = "Sum"
  period              = 300
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.ssh_config_alerts.arn]
  treat_missing_data  = "notBreaching"
}

resource "aws_sns_topic_policy" "ssh_config_alerts" {
  arn = aws_sns_topic.ssh_config_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "SNS:Publish"
      Resource  = aws_sns_topic.ssh_config_alerts.arn
    }]
  })
}""",
                alert_severity="high",
                alert_title="SSH Configuration File Abuse Detected",
                alert_description_template=(
                    "SSH configuration file modification or suspicious SSH command-line detected on {computer}. "
                    "This may indicate indirect command execution via ProxyCommand or LocalCommand abuse."
                ),
                investigation_steps=[
                    "Review the SSH configuration file at %USERPROFILE%\\.ssh\\config",
                    "Check for ProxyCommand and LocalCommand directives with suspicious commands",
                    "Examine recent SSH connection attempts and destinations",
                    "Identify the user account that modified the SSH config file",
                    "Review Windows Event ID 4663 (File Access) for config file modifications",
                    "Check for ssh.exe executions with -o flag in command-line history",
                    "Investigate parent process that modified the SSH config",
                ],
                containment_actions=[
                    "Remove malicious ProxyCommand and LocalCommand entries from SSH config",
                    "Restore SSH config file from known good backup",
                    "Restrict write permissions on .ssh directory and config files",
                    "Disable SSH client if not required for business operations",
                    "Audit SSH usage patterns across all Windows instances",
                    "Implement file integrity monitoring for SSH configuration files",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist authorised SSH proxy and jump host configurations",
            detection_coverage="70% - detects SSH config modifications and -o flag usage",
            evasion_considerations="Attackers may use alternative configuration methods or modify permissions to hide changes",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1.5 hours",
            estimated_monthly_cost="$5-15 depending on log volume",
            prerequisites=[
                "File access auditing enabled on Windows",
                "CloudWatch Agent configured to forward file audit logs",
                "Sysmon or enhanced logging for file modifications",
            ],
        ),
        # Strategy 3: GCP Windows Instance Detection
        DetectionStrategy(
            strategy_id="t1202-gcp-indirect-exec",
            name="GCP: Detect Indirect Command Execution on Windows GCE",
            description=(
                "Monitor GCP Cloud Logging for indirect command execution utilities on "
                "Windows Compute Engine instances through process creation events."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_instance"
jsonPayload.EventID=4688
(jsonPayload.ParentProcessName=~"forfiles\\.exe|pcalua\\.exe|wsl\\.exe|scriptrunner\\.exe|ssh\\.exe")
(jsonPayload.NewProcessName=~"powershell\\.exe|cmd\\.exe|msiexec\\.exe|regsvr32\\.exe|wscript\\.exe")""",
                gcp_terraform_template="""# GCP: Detect indirect command execution on Windows GCE instances

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "email" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log-based metric for indirect execution
resource "google_logging_metric" "indirect_exec" {
  project = var.project_id
  name    = "indirect-command-execution"
  filter  = <<-EOT
    resource.type="gce_instance"
    jsonPayload.EventID=4688
    (jsonPayload.ParentProcessName=~"forfiles\\.exe|pcalua\\.exe|wsl\\.exe|scriptrunner\\.exe|ssh\\.exe")
    (jsonPayload.NewProcessName=~"powershell\\.exe|cmd\\.exe|msiexec\\.exe|regsvr32\\.exe|wscript\\.exe")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "instance_id"
      value_type  = "STRING"
      description = "Instance where indirect execution was detected"
    }
    labels {
      key         = "parent_process"
      value_type  = "STRING"
      description = "Indirect execution utility used"
    }
  }

  label_extractors = {
    instance_id    = "EXTRACT(resource.labels.instance_id)"
    parent_process = "EXTRACT(jsonPayload.ParentProcessName)"
  }
}

# Step 3: Create alert policy
resource "google_monitoring_alert_policy" "indirect_exec" {
  project      = var.project_id
  display_name = "T1202: Indirect Command Execution Detected"
  combiner     = "OR"

  conditions {
    display_name = "Indirect execution utility spawned suspicious process"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.indirect_exec.name}\" resource.type=\"gce_instance\""
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
    content   = "Indirect command execution detected on Windows GCE instance. Investigate for defence evasion activity using forfiles, pcalua, WSL, or SSH utilities."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="high",
                alert_title="GCP: Indirect Command Execution Detected",
                alert_description_template=(
                    "Indirect command execution detected on Windows GCE instance {instance_id}. "
                    "Parent utility: {parent_process}. Spawned process: {new_process_name}. "
                    "Investigate for defence evasion."
                ),
                investigation_steps=[
                    "Review the Cloud Logging entry for full process creation details",
                    "Examine the command-line arguments passed to spawned process",
                    "Identify the user account that executed the indirect utility",
                    "Check Windows Event Viewer for Event ID 4688 context",
                    "Review the instance's service account recent API activity",
                    "Check for subsequent network connections or data transfers",
                    "Investigate parent process chain to identify initial execution vector",
                ],
                containment_actions=[
                    "Terminate suspicious spawned processes via remote command",
                    "Stop the GCE instance if active compromise is confirmed",
                    "Create instance snapshot for forensic investigation",
                    "Revoke instance service account credentials",
                    "Review and strengthen application control policies",
                    "Disable WSL and unused utilities if not business-required",
                    "Implement stricter command-line execution policies",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist authorised administrative scripts using forfiles; exclude known WSL development workflows",
            detection_coverage="75% - captures indirect execution patterns with common utilities",
            evasion_considerations="Custom or renamed utilities may bypass detection signatures",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1.5 hours",
            estimated_monthly_cost="$10-25",
            prerequisites=[
                "Cloud Logging API enabled",
                "Ops Agent or Cloud Logging agent installed on Windows GCE instances",
                "Windows Event logging configured for process creation",
            ],
        ),
        # Strategy 4: WSL-Specific Detection
        DetectionStrategy(
            strategy_id="t1202-wsl-detection",
            name="AWS: Detect WSL Abuse for Command Execution",
            description=(
                "Monitor for abuse of Windows Subsystem for Linux (wsl.exe) to execute "
                "Linux commands and binaries whilst bypassing Windows security controls."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, EventID, Computer, ProcessName, CommandLine, ParentProcessName
| filter EventID = 4688
| filter ProcessName like /wsl[.]exe|wslhost[.]exe|bash[.]exe/i
| filter CommandLine like /curl|wget|nc|ncat|powershell|sh -c|bash -c/i
| stats count() as executions by Computer, ProcessName, CommandLine, bin(10m)
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect WSL abuse for indirect command execution

Parameters:
  CloudWatchLogGroup:
    Type: String
    Description: Log group containing Windows Security Event logs
    Default: /aws/ec2/windows/security
  AlertEmail:
    Type: String
    Description: Email for alerts

Resources:
  # Step 1: Create SNS topic
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      KmsMasterKeyId: alias/aws/sns
      DisplayName: WSL Abuse Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Create metric filter for suspicious WSL usage
  WSLAbuseFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudWatchLogGroup
      FilterPattern: '{ ($.EventID = 4688) && ($.ProcessName = "*wsl.exe" || $.ProcessName = "*bash.exe") && ($.CommandLine = "*curl*" || $.CommandLine = "*wget*" || $.CommandLine = "*nc*" || $.CommandLine = "*ncat*" || $.CommandLine = "*sh -c*" || $.CommandLine = "*bash -c*") }'
      MetricTransformations:
        - MetricName: WSLCommandAbuse
          MetricNamespace: Security/T1202
          MetricValue: "1"
          DefaultValue: 0

  # Step 3: Create alarm for WSL abuse
  WSLAbuseAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1202-WSLCommandAbuse
      AlarmDescription: Suspicious WSL command execution detected
      MetricName: WSLCommandAbuse
      Namespace: Security/T1202
      Statistic: Sum
      Period: 300
      Threshold: 1
      ComparisonOperator: GreaterThanOrEqualToThreshold
      EvaluationPeriods: 1
      AlarmActions:
        - !Ref AlertTopic
      TreatMissingData: notBreaching

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref AlertTopic
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: cloudwatch.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic""",
                terraform_template="""# Detect WSL abuse for indirect command execution

variable "cloudwatch_log_group" {
  type        = string
  description = "Log group containing Windows Security Event logs"
  default     = "/aws/ec2/windows/security"
}

variable "alert_email" {
  type        = string
  description = "Email for alerts"
}

# Step 1: Create SNS topic
resource "aws_sns_topic" "wsl_abuse_alerts" {
  name         = "wsl-abuse-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "WSL Abuse Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.wsl_abuse_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for suspicious WSL usage
resource "aws_cloudwatch_log_metric_filter" "wsl_abuse" {
  name           = "wsl-command-abuse"
  log_group_name = var.cloudwatch_log_group
  pattern        = "{ ($.EventID = 4688) && ($.ProcessName = \"*wsl.exe\" || $.ProcessName = \"*bash.exe\") && ($.CommandLine = \"*curl*\" || $.CommandLine = \"*wget*\" || $.CommandLine = \"*nc*\" || $.CommandLine = \"*ncat*\" || $.CommandLine = \"*sh -c*\" || $.CommandLine = \"*bash -c*\") }"

  metric_transformation {
    name          = "WSLCommandAbuse"
    namespace     = "Security/T1202"
    value         = "1"
    default_value = 0
  }
}

# Step 3: Create alarm for WSL abuse
resource "aws_cloudwatch_metric_alarm" "wsl_abuse" {
  alarm_name          = "T1202-WSLCommandAbuse"
  alarm_description   = "Suspicious WSL command execution detected"
  metric_name         = "WSLCommandAbuse"
  namespace           = "Security/T1202"
  statistic           = "Sum"
  period              = 300
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.wsl_abuse_alerts.arn]
  treat_missing_data  = "notBreaching"
}

resource "aws_sns_topic_policy" "wsl_abuse_alerts" {
  arn = aws_sns_topic.wsl_abuse_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "SNS:Publish"
      Resource  = aws_sns_topic.wsl_abuse_alerts.arn
    }]
  })
}""",
                alert_severity="high",
                alert_title="WSL Abuse for Command Execution Detected",
                alert_description_template=(
                    "Suspicious WSL command execution detected on {computer}. "
                    "Process: {process_name}. Command: {command_line}. "
                    "This may indicate use of WSL to bypass Windows security controls."
                ),
                investigation_steps=[
                    "Review the full WSL command-line to identify malicious activity",
                    "Check which user account executed the WSL command",
                    "Verify if WSL is authorised for business use on this instance",
                    "Examine WSL distribution logs for executed Linux commands",
                    "Review parent process that invoked wsl.exe",
                    "Check for network connections from WSL processes",
                    "Investigate recent file downloads or data transfers via WSL",
                    "Review WSL installation date and distribution configurations",
                ],
                containment_actions=[
                    "Terminate WSL processes if suspicious activity confirmed",
                    "Disable WSL feature if not required for business operations",
                    "Unregister WSL distributions using 'wsl --unregister <distro>'",
                    "Review and restrict WSL usage via Group Policy",
                    "Block WSL network access through Windows Firewall if needed",
                    "Audit and remove unauthorised WSL distributions",
                    "Implement application control to restrict wsl.exe execution",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist authorised developer workflows and CI/CD pipelines using WSL",
            detection_coverage="85% - captures suspicious WSL command patterns",
            evasion_considerations="Benign-looking commands or encoded payloads may evade pattern matching",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-15 depending on log volume",
            prerequisites=[
                "CloudWatch Agent installed on Windows instances",
                "Windows Process Creation auditing enabled",
                "Process command-line logging enabled",
            ],
        ),
    ],
    recommended_order=[
        "t1202-aws-indirect-utils",
        "t1202-wsl-detection",
        "t1202-ssh-config-abuse",
        "t1202-gcp-indirect-exec",
    ],
    total_effort_hours=5.5,
    coverage_improvement="+12% improvement for Defence Evasion tactic",
)
