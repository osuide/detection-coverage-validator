"""
T1112 - Modify Registry

Adversaries may interact with the Windows Registry to hide configuration information,
remove information as part of cleaning up, or as part of other techniques to aid in
persistence and execution.
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
    technique_id="T1112",
    technique_name="Modify Registry",
    tactic_ids=["TA0003", "TA0005"],  # Persistence, Defense Evasion
    mitre_url="https://attack.mitre.org/techniques/T1112/",
    threat_context=ThreatContext(
        description=(
            "Adversaries interact with the Windows Registry to support defence evasion, "
            "persistence, and execution. Registry modifications can hide malicious payloads, "
            "disable security features, enable macro execution, or establish persistence mechanisms. "
            "In cloud environments, this affects Windows EC2 instances and GCE VMs where attackers "
            "modify registry keys to disable Windows Defender, create Run keys for persistence, "
            "enable WDigest credential caching, or bypass User Account Control (UAC) protections."
        ),
        attacker_goal="Modify Windows Registry to establish persistence, disable defences, or enable credential theft",
        why_technique=[
            "Registry Run keys provide persistent execution across reboots",
            "Disabling Windows Defender and security tools removes detection capabilities",
            "Enabling WDigest stores plaintext credentials in memory for later theft",
            "Modifying Office macro settings allows malicious document execution",
            "UAC bypass registry changes enable privilege escalation without prompts",
            "Hiding registry keys with null characters evades forensic tools",
            "Modifying RemoteRegistry service enables lateral movement",
            "Changes persist after system restart without file system modifications",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="stable",
        severity_score=7,
        severity_reasoning=(
            "Registry modification is a critical indicator of malicious activity on Windows systems. "
            "While some registry changes are legitimate administrative actions, modifications to "
            "security settings, persistence locations, or defence evasion keys often signal active "
            "compromise. The technique's severity is heightened when combined with other indicators "
            "such as suspicious process execution or unauthorised access patterns."
        ),
        business_impact=[
            "Persistent backdoor access to cloud Windows instances",
            "Disabled endpoint protection exposing instances to malware",
            "Credential theft through WDigest enabling lateral movement",
            "Bypassed security controls allowing undetected malicious activity",
            "Compliance violations from disabled security features",
            "Extended attacker dwell time through stealth persistence",
            "Potential data exfiltration from compromised instances",
        ],
        typical_attack_phase="defence_evasion",
        often_precedes=["T1003", "T1021", "T1486", "T1562"],
        often_follows=["T1078", "T1190", "T1133", "T1059"],
    ),
    detection_strategies=[
        # Strategy 1: AWS GuardDuty Runtime Monitoring
        DetectionStrategy(
            strategy_id="t1112-guardduty-runtime",
            name="AWS GuardDuty Runtime Monitoring for Registry Modifications",
            description=(
                "AWS GuardDuty Runtime Monitoring detects suspicious registry modifications on "
                "Windows EC2 instances, including changes to security settings, persistence keys, "
                "and defence evasion registry locations through behavioural analysis."
            ),
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "DefenseEvasion:Runtime/ProcessInjection.Proc",
                    "Execution:Runtime/NewBinaryExecuted",
                    "PrivilegeEscalation:Runtime/SuspiciousCommand",
                    "DefenseEvasion:Runtime/FilelessExecution",
                ],
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: GuardDuty Runtime Monitoring for registry modification detection

Parameters:
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # Step 1: Enable GuardDuty with Runtime Monitoring
  GuardDutyDetector:
    Type: AWS::GuardDuty::Detector
    Properties:
      Enable: true
      Features:
        - Name: RUNTIME_MONITORING
          Status: ENABLED

  # Step 2: Create SNS topic for alerts
  RegistryModAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: Registry Modification Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 3: DLQ for EventBridge
  DLQ:
    Type: AWS::SQS::Queue
    Properties:
      MessageRetentionPeriod: 1209600

  # Step 4: Route defence evasion findings to email
  RegistryModificationRule:
    Type: AWS::Events::Rule
    Properties:
      Name: T1112-RegistryModification
      Description: Alert on suspicious registry modifications
      EventPattern:
        source: [aws.guardduty]
        detail-type:
          - GuardDuty Finding
        detail:
          type:
            - prefix: "DefenseEvasion:Runtime"
            - prefix: "Persistence:Runtime"
            - prefix: "PrivilegeEscalation:Runtime"
      State: ENABLED
      Targets:
        - Id: AlertTopic
          Arn: !Ref RegistryModAlertTopic
          RetryPolicy:
            MaximumRetryAttempts: 8
            MaximumEventAgeInSeconds: 3600
          DeadLetterConfig:
            Arn: !GetAtt DLQ.Arn

  # Step 5: Topic policy with scoped conditions
  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref RegistryModAlertTopic]
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Sid: AllowEventBridgePublish
            Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref RegistryModAlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn: !GetAtt RegistryModificationRule.Arn""",
                terraform_template="""# GuardDuty Runtime Monitoring for registry modifications

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
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

# Step 2: Create SNS topic for alerts
resource "aws_sns_topic" "registry_mod_alerts" {
  name         = "registry-modification-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "Registry Modification Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.registry_mod_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 3: DLQ for EventBridge
resource "aws_sqs_queue" "dlq" {
  name                      = "registry-modification-alerts-dlq"
  message_retention_seconds = 1209600
}

# SQS Queue Policy for EventBridge DLQ (CRITICAL)
# Without this, EventBridge cannot send failed events to the DLQ
data "aws_iam_policy_document" "eventbridge_dlq_policy" {
  statement {
    sid     = "AllowEventBridgeToSendToDLQ"
    effect  = "Allow"
    actions = ["sqs:SendMessage"]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    resources = [aws_sqs_queue.dlq.arn]

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_cloudwatch_event_rule.registry_modification.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "event_dlq" {
  queue_url = aws_sqs_queue.dlq.url
  policy    = data.aws_iam_policy_document.eventbridge_dlq_policy.json
}

# Step 4: Route defence evasion findings to email
resource "aws_cloudwatch_event_rule" "registry_modification" {
  name        = "guardduty-registry-modification"
  description = "Alert on suspicious registry modifications"
  event_pattern = jsonencode({
    source = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    detail = {
      type = [
        { prefix = "DefenseEvasion:Runtime" },
        { prefix = "Persistence:Runtime" },
        { prefix = "PrivilegeEscalation:Runtime" }
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.registry_modification.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.registry_mod_alerts.arn

  retry_policy {
    maximum_retry_attempts       = 8
    maximum_event_age_in_seconds = 3600
  }

  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
  }
  input_transformer {
    input_paths = {
      account    = "$.account"
      region     = "$.region"
      time       = "$.time"
      type       = "$.detail.type"
      severity   = "$.detail.severity"
      title      = "$.detail.title"
      description = "$.detail.description"
    }

    input_template = <<-EOT
"GuardDuty Finding Alert
Time: <time>
Account: <account>
Region: <region>
Finding: <type>
Severity: <severity>
Title: <title>
Description: <description>
Action: Review finding in GuardDuty console and investigate"
EOT
  }

}

# Step 5: Topic policy with scoped conditions
data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.registry_mod_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowEventBridgePublish"
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.registry_mod_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.registry_modification.arn
        }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="GuardDuty: Suspicious Registry Modification Detected",
                alert_description_template=(
                    "Suspicious registry modification detected on instance {instance_id}. "
                    "Finding: {finding_type}. This may indicate defence evasion or persistence establishment."
                ),
                investigation_steps=[
                    "Review the GuardDuty finding details and affected Windows instance",
                    "Check Windows Event Viewer System and Security logs (Event ID 4657, 4660, 4663)",
                    "Identify which registry keys were modified and by which process",
                    "Review the process that made the registry changes and its parent process",
                    "Check for modifications to critical keys (Run, RunOnce, Windows Defender, WDigest)",
                    "Examine recent user logins and API calls from the instance IAM role",
                    "Search for additional indicators of compromise on the instance",
                ],
                containment_actions=[
                    "Isolate the instance by modifying security group rules",
                    "Create a forensic snapshot before making changes",
                    "Revert malicious registry changes if identified",
                    "Terminate suspicious processes making registry modifications",
                    "Rotate instance IAM role credentials immediately",
                    "Re-enable any disabled security features (Windows Defender, UAC)",
                    "Terminate and rebuild the instance if compromise is confirmed",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline legitimate administrative registry changes; exclude authorised system management tools",
            detection_coverage="60% - detects suspicious runtime registry modification patterns",
            evasion_considerations="Attackers may make gradual changes or use legitimate tools to evade behavioural detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="45 minutes",
            estimated_monthly_cost="$4.60 per instance per month for Runtime Monitoring",
            prerequisites=[
                "GuardDuty enabled",
                "SSM Agent on EC2 instances for Runtime Monitoring",
            ],
        ),
        # Strategy 2: Windows Registry Event Monitoring
        DetectionStrategy(
            strategy_id="t1112-registry-events",
            name="Windows Registry Event Monitoring via CloudWatch",
            description=(
                "Monitor Windows Security Event Logs for registry modifications through Event IDs "
                "4657 (Registry Value Modified), 4660 (Object Deleted), and 4663 (Object Access), "
                "focusing on high-value persistence and security-related registry keys."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, EventID, Computer, ProcessName, ObjectName, ObjectValueName
| filter EventID in [4657, 4660, 4663]
| filter ObjectName like /Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run|Software\\\\Microsoft\\\\Windows Defender|SYSTEM\\\\CurrentControlSet\\\\Services|WDigest|UserInitMprLogonScript|SafeDllSearchMode/
| stats count() as modifications by Computer, ProcessName, ObjectName, bin(10m)
| filter modifications > 2
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Windows Registry event monitoring for T1112

Parameters:
  CloudWatchLogGroup:
    Type: String
    Description: Log group containing Windows Security Event logs
    Default: /aws/ec2/windows/security
  SNSTopicArn:
    Type: String
    Description: SNS topic for alerts

Resources:
  # Step 1: Create metric filter for Run key modifications
  RunKeyModificationFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudWatchLogGroup
      FilterPattern: '[EventID="4657", ObjectName="*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run*"]'
      MetricTransformations:
        - MetricName: RunKeyModifications
          MetricNamespace: Security/T1112
          MetricValue: "1"

  # Step 2: Create alarm for persistence registry changes
  PersistenceRegistryAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1112-PersistenceRegistry
      AlarmDescription: Suspicious registry Run key modification detected
      MetricName: RunKeyModifications
      Namespace: Security/T1112
      Statistic: Sum
      Period: 600
      EvaluationPeriods: 1
      Threshold: 1
      ComparisonOperator: GreaterThanThreshold
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref SNSTopicArn

  # Step 3: Monitor security-related registry changes
  SecurityRegistryFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudWatchLogGroup
      FilterPattern: '[EventID="4657", ObjectName="*Windows Defender*" || ObjectName="*WDigest*" || ObjectName="*SafeDllSearchMode*"]'
      MetricTransformations:
        - MetricName: SecurityRegistryChanges
          MetricNamespace: Security/T1112
          MetricValue: "1"

  SecurityRegistryAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1112-SecurityRegistry
      AlarmDescription: Security-related registry modification detected
      MetricName: SecurityRegistryChanges
      Namespace: Security/T1112
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 1
      ComparisonOperator: GreaterThanOrEqualToThreshold
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref SNSTopicArn""",
                terraform_template="""# Windows Registry event monitoring

variable "cloudwatch_log_group" {
  type        = string
  description = "Log group containing Windows Security Event logs"
  default     = "/aws/ec2/windows/security"
}

variable "alert_email" {
  type = string
}

resource "aws_sns_topic" "alerts" {
  name = "registry-modification-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 1: Create metric filter for Run key modifications
resource "aws_cloudwatch_log_metric_filter" "run_key_modifications" {
  name           = "registry-run-key-modifications"
  log_group_name = var.cloudwatch_log_group
  pattern        = "[EventID=\"4657\", ObjectName=\"*\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run*\"]"

  metric_transformation {
    name      = "RunKeyModifications"
    namespace = "Security/T1112"
    value     = "1"
  }
}

# Step 2: Create alarm for persistence registry changes
resource "aws_cloudwatch_metric_alarm" "persistence_registry" {
  alarm_name          = "T1112-PersistenceRegistry"
  alarm_description   = "Suspicious registry Run key modification detected"
  metric_name         = "RunKeyModifications"
  namespace           = "Security/T1112"
  statistic           = "Sum"
  period              = 600
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}

# Step 3: Monitor security-related registry changes
resource "aws_cloudwatch_log_metric_filter" "security_registry_changes" {
  name           = "security-registry-changes"
  log_group_name = var.cloudwatch_log_group
  pattern        = "[EventID=\"4657\", ObjectName=\"*Windows Defender*\" || ObjectName=\"*WDigest*\" || ObjectName=\"*SafeDllSearchMode*\"]"

  metric_transformation {
    name      = "SecurityRegistryChanges"
    namespace = "Security/T1112"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "security_registry" {
  alarm_name          = "T1112-SecurityRegistry"
  alarm_description   = "Security-related registry modification detected"
  metric_name         = "SecurityRegistryChanges"
  namespace           = "Security/T1112"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

# Step 4: SNS topic policy
data "aws_caller_identity" "current" {}

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
}""",
                alert_severity="high",
                alert_title="Suspicious Registry Modification Detected",
                alert_description_template=(
                    "Registry modification detected on {computer}. Process: {process_name}. "
                    "Registry key: {object_name}. Event ID: {event_id}. "
                    "This may indicate persistence establishment or security tool tampering."
                ),
                investigation_steps=[
                    "Identify the specific registry key and value that was modified",
                    "Review the process that made the change and its command line",
                    "Check if the modification was part of authorised administrative activity",
                    "Examine the parent process to understand the execution chain",
                    "Review Event ID 4688 (Process Creation) for related process starts",
                    "Check for other registry modifications by the same process",
                    "Investigate the user account that initiated the change",
                    "Search for known malware patterns matching the registry change",
                ],
                containment_actions=[
                    "Revert the malicious registry modification using regedit or PowerShell",
                    "Terminate the process that made the unauthorised change",
                    "Disable the user account if compromise is suspected",
                    "Remove any malicious registry Run keys or startup entries",
                    "Re-enable Windows Defender or other disabled security features",
                    "Check and restore UAC and other security policy settings",
                    "Scan the instance with updated antivirus signatures",
                    "Rebuild the instance if multiple malicious changes are found",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist legitimate software installation and system management tools; baseline normal administrative registry changes",
            detection_coverage="80% - comprehensive coverage for high-value registry key modifications",
            evasion_considerations="Attackers may disable registry auditing or modify less-monitored registry keys",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$10-25 depending on log volume",
            prerequisites=[
                "CloudWatch Agent installed on Windows instances",
                "Windows Registry auditing enabled via Group Policy or Local Security Policy",
                "CloudWatch Logs configured to receive Windows Event logs",
            ],
        ),
        # Strategy 3: PowerShell Registry Modification Detection
        DetectionStrategy(
            strategy_id="t1112-powershell-registry",
            name="PowerShell Registry Modification Detection",
            description=(
                "Detect registry modifications made through PowerShell cmdlets such as "
                "Set-ItemProperty, New-ItemProperty, Remove-ItemProperty, and direct registry "
                "provider access, which are common methods for scripted registry manipulation."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, @message, Computer, CommandLine, ScriptBlockText
| filter @message like /Set-ItemProperty|New-ItemProperty|Remove-ItemProperty|HKLM:|HKCU:|reg add|reg delete|reg modify/
| filter @message like /Run|Windows Defender|WDigest|SafeDllSearchMode|UserInitMprLogonScript|EnableLUA|ConsentPromptBehaviorAdmin/
| stats count() as commands by Computer, bin(10m)
| sort @timestamp desc""",
                cloudformation_template='''AWSTemplateFormatVersion: '2010-09-09'
Description: PowerShell registry modification detection

Parameters:
  CloudWatchLogGroup:
    Type: String
    Description: Log group containing PowerShell logs
    Default: /aws/ec2/windows/powershell
  SNSTopicArn:
    Type: String
    Description: SNS topic for alerts

Resources:
  # Step 1: Create metric filter for PowerShell registry cmdlets
  PowerShellRegistryFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudWatchLogGroup
      FilterPattern: '[time, computer, level, message="*Set-ItemProperty*" || message="*New-ItemProperty*" || message="*reg add*"]'
      MetricTransformations:
        - MetricName: PowerShellRegistryCommands
          MetricNamespace: Security/T1112
          MetricValue: "1"

  # Step 2: Create alarm for PowerShell registry activity
  PowerShellRegistryAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1112-PowerShellRegistry
      AlarmDescription: PowerShell registry modification detected
      MetricName: PowerShellRegistryCommands
      Namespace: Security/T1112
      Statistic: Sum
      Period: 600
      EvaluationPeriods: 1
      Threshold: 3
      ComparisonOperator: GreaterThanThreshold
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref SNSTopicArn

  # Step 3: Monitor critical registry key modifications
  CriticalKeyFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudWatchLogGroup
      FilterPattern: '[time, computer, level, message="*Windows Defender*DisableAntiSpyware*" || message="*WDigest*UseLogonCredential*" || message="*EnableLUA*0*"]'
      MetricTransformations:
        - MetricName: CriticalRegistryModifications
          MetricNamespace: Security/T1112
          MetricValue: "1"''',
                terraform_template="""# PowerShell registry modification detection

variable "cloudwatch_log_group" {
  type        = string
  description = "Log group containing PowerShell logs"
  default     = "/aws/ec2/windows/powershell"
}

variable "alert_email" {
  type = string
}

resource "aws_sns_topic" "alerts" {
  name = "powershell-registry-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 1: Create metric filter for PowerShell registry cmdlets
resource "aws_cloudwatch_log_metric_filter" "powershell_registry" {
  name           = "powershell-registry-commands"
  log_group_name = var.cloudwatch_log_group
  pattern        = "[time, computer, level, message=\"*Set-ItemProperty*\" || message=\"*New-ItemProperty*\" || message=\"*reg add*\"]"

  metric_transformation {
    name      = "PowerShellRegistryCommands"
    namespace = "Security/T1112"
    value     = "1"
  }
}

# Step 2: Create alarm for PowerShell registry activity
resource "aws_cloudwatch_metric_alarm" "powershell_registry" {
  alarm_name          = "T1112-PowerShellRegistry"
  alarm_description   = "PowerShell registry modification detected"
  metric_name         = "PowerShellRegistryCommands"
  namespace           = "Security/T1112"
  statistic           = "Sum"
  period              = 600
  evaluation_periods  = 1
  threshold           = 3
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}

# Step 3: Monitor critical registry key modifications
resource "aws_cloudwatch_log_metric_filter" "critical_registry_mods" {
  name           = "critical-registry-modifications"
  log_group_name = var.cloudwatch_log_group
  pattern        = "[time, computer, level, message=\"*Windows Defender*DisableAntiSpyware*\" || message=\"*WDigest*UseLogonCredential*\" || message=\"*EnableLUA*0*\"]"

  metric_transformation {
    name      = "CriticalRegistryModifications"
    namespace = "Security/T1112"
    value     = "1"
  }
}

# Step 4: SNS topic policy
data "aws_caller_identity" "current" {}

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
}""",
                alert_severity="high",
                alert_title="PowerShell Registry Modification Detected",
                alert_description_template=(
                    "PowerShell registry modification detected on {computer}. "
                    "Command: {command_line}. This may indicate scripted defence evasion or persistence."
                ),
                investigation_steps=[
                    "Review the full PowerShell script block text to see complete command",
                    "Identify what registry key and value were modified",
                    "Check if the PowerShell execution was part of authorised automation",
                    "Review PowerShell Event ID 4104 (Script Block Logging) for full context",
                    "Examine the user account that executed the PowerShell command",
                    "Check for PowerShell execution policy bypasses or obfuscation",
                    "Look for other PowerShell commands executed around the same time",
                    "Investigate the source of the PowerShell script (local file, remote download)",
                ],
                containment_actions=[
                    "Terminate active PowerShell processes if still running",
                    "Revert the malicious registry changes identified in the script",
                    "Disable PowerShell remoting if it was enabled by the script",
                    "Review and restrict PowerShell execution policy settings",
                    "Delete any malicious PowerShell scripts from the file system",
                    "Revoke credentials for the user account that ran the script",
                    "Enable PowerShell Constrained Language Mode to limit future abuse",
                    "Review and harden AppLocker or WDAC policies",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline authorised configuration management scripts; whitelist known administrative PowerShell scripts and scheduled tasks",
            detection_coverage="75% - covers PowerShell-based registry modifications comprehensively",
            evasion_considerations="Attackers may use obfuscation, execute from memory, or disable PowerShell logging",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1.5 hours",
            estimated_monthly_cost="$10-20 depending on log volume",
            prerequisites=[
                "PowerShell Script Block Logging enabled (Event ID 4104)",
                "CloudWatch Agent configured to forward PowerShell operational logs",
            ],
        ),
        # Strategy 4: GCP Windows Registry Monitoring
        DetectionStrategy(
            strategy_id="t1112-gcp-registry",
            name="GCP: Windows Registry Modification Detection",
            description=(
                "Monitor GCP Cloud Logging for registry modifications on Windows Compute Engine "
                "instances through Windows Event logs and Ops Agent telemetry data."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_instance"
(jsonPayload.EventID=4657 OR jsonPayload.EventID=4660 OR jsonPayload.EventID=4663)
(jsonPayload.ObjectName=~".*\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run.*"
OR jsonPayload.ObjectName=~".*Windows Defender.*"
OR jsonPayload.ObjectName=~".*WDigest.*"
OR jsonPayload.ObjectName=~".*SafeDllSearchMode.*"
OR textPayload=~"Set-ItemProperty|New-ItemProperty|reg add")""",
                gcp_terraform_template="""# GCP: Windows Registry modification detection

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type = string
}

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "email" {
  project      = var.project_id
  display_name = "Registry Modification Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log-based metric for registry modifications
resource "google_logging_metric" "registry_modifications" {
  project = var.project_id
  name    = "registry-modifications"
  filter  = <<-EOT
    resource.type="gce_instance"
    (jsonPayload.EventID=4657 OR jsonPayload.EventID=4660 OR jsonPayload.EventID=4663)
    (jsonPayload.ObjectName=~".*\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run.*"
    OR jsonPayload.ObjectName=~".*Windows Defender.*"
    OR jsonPayload.ObjectName=~".*WDigest.*"
    OR jsonPayload.ObjectName=~".*SafeDllSearchMode.*"
    OR textPayload=~"Set-ItemProperty|New-ItemProperty|reg add")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "instance_id"
      value_type  = "STRING"
      description = "Instance where registry modification occurred"
    }
    labels {
      key         = "registry_key"
      value_type  = "STRING"
      description = "Registry key that was modified"
    }
  }

  label_extractors = {
    instance_id  = "EXTRACT(resource.labels.instance_id)"
    registry_key = "EXTRACT(jsonPayload.ObjectName)"
  }
}

# Step 3: Create alert policy for registry modifications
resource "google_monitoring_alert_policy" "registry_modifications" {
  project      = var.project_id
  display_name = "T1112: Suspicious Registry Modification Detected"
  combiner     = "OR"
  conditions {
    display_name = "Registry modification activity"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.registry_modifications.name}\" resource.type=\"gce_instance\""
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
    content   = "Suspicious Windows Registry modification detected. Registry changes may indicate persistence establishment, defence evasion, or security tool tampering. Investigate immediately."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="high",
                alert_title="GCP: Suspicious Registry Modification Detected",
                alert_description_template=(
                    "Registry modification detected on Windows GCE instance {instance_id}. "
                    "Registry key: {registry_key}. Event ID: {event_id}. Investigate for malicious activity."
                ),
                investigation_steps=[
                    "Review the Cloud Logging entry for complete event details",
                    "Identify the process and user that made the registry change",
                    "Check if the modification was part of authorised administrative work",
                    "Review the instance's service account activity in Cloud Audit Logs",
                    "Examine Windows Event Viewer for related security events",
                    "Check for other suspicious registry modifications on the instance",
                    "Review VPC Flow Logs for unusual network activity",
                    "Investigate recent instance metadata access patterns",
                ],
                containment_actions=[
                    "Stop the GCE instance to prevent further modifications",
                    "Create a disk snapshot for forensic analysis",
                    "Revert malicious registry changes using snapshot or backup",
                    "Revoke the instance's service account credentials",
                    "Update firewall rules to isolate the instance",
                    "Re-enable any disabled security features (Windows Defender)",
                    "Remove malicious Run keys or startup entries",
                    "Rebuild the instance from a known good image if compromised",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal software installations and administrative changes; whitelist authorised configuration management tools",
            detection_coverage="75% - comprehensive coverage for Windows registry modifications on GCP",
            evasion_considerations="Attackers may disable Windows Event logging or use direct API calls to evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$15-30",
            prerequisites=[
                "Cloud Logging API enabled",
                "Ops Agent installed on Windows GCE instances",
                "Windows Registry auditing enabled",
                "Windows Event logging configured in Ops Agent",
            ],
        ),
        # Strategy 5: Registry Tool Execution Detection
        DetectionStrategy(
            strategy_id="t1112-registry-tools",
            name="Detect Registry Tool and Command Execution",
            description=(
                "Monitor for execution of registry manipulation tools and commands including "
                "reg.exe, regedit.exe, and PowerShell registry cmdlets with suspicious parameters "
                "targeting security-critical registry keys."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, instanceId, ProcessName, CommandLine, ParentProcessName
| filter ProcessName in ["reg.exe", "regedit.exe", "powershell.exe", "pwsh.exe"]
| filter CommandLine like /add|delete|import|Windows Defender|WDigest|Run|EnableLUA|DisableAntiSpyware/
| stats count() as executions by instanceId, ProcessName, CommandLine, bin(10m)
| filter executions > 1
| sort @timestamp desc""",
                cloudformation_template='''AWSTemplateFormatVersion: '2010-09-09'
Description: Registry tool execution detection

Parameters:
  CloudWatchLogGroup:
    Type: String
    Description: Log group containing process execution logs
  SNSTopicArn:
    Type: String
    Description: SNS topic for alerts

Resources:
  # Step 1: Create metric filter for reg.exe usage
  RegExeFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudWatchLogGroup
      FilterPattern: '[time, instance, process="reg.exe", command="*add*" || command="*delete*" || command="*import*"]'
      MetricTransformations:
        - MetricName: RegistryToolExecution
          MetricNamespace: Security/T1112
          MetricValue: "1"

  # Step 2: Create alarm for registry tool usage
  RegistryToolAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1112-RegistryToolExecution
      AlarmDescription: Suspicious registry tool execution detected
      MetricName: RegistryToolExecution
      Namespace: Security/T1112
      Statistic: Sum
      Period: 600
      EvaluationPeriods: 1
      Threshold: 2
      ComparisonOperator: GreaterThanThreshold
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref SNSTopicArn

  # Step 3: Monitor critical registry modifications via reg.exe
  CriticalRegModFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudWatchLogGroup
      FilterPattern: '[time, instance, process, command="*DisableAntiSpyware*" || command="*UseLogonCredential*" || command="*EnableLUA*"]'
      MetricTransformations:
        - MetricName: CriticalRegToolMods
          MetricNamespace: Security/T1112
          MetricValue: "1"''',
                terraform_template="""# Registry tool execution detection

variable "cloudwatch_log_group" {
  type        = string
  description = "Log group containing process execution logs"
}

variable "alert_email" {
  type = string
}

resource "aws_sns_topic" "alerts" {
  name = "registry-tool-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 1: Create metric filter for reg.exe usage
resource "aws_cloudwatch_log_metric_filter" "reg_exe_execution" {
  name           = "registry-tool-execution"
  log_group_name = var.cloudwatch_log_group
  pattern        = "[time, instance, process=\"reg.exe\", command=\"*add*\" || command=\"*delete*\" || command=\"*import*\"]"

  metric_transformation {
    name      = "RegistryToolExecution"
    namespace = "Security/T1112"
    value     = "1"
  }
}

# Step 2: Create alarm for registry tool usage
resource "aws_cloudwatch_metric_alarm" "registry_tool" {
  alarm_name          = "T1112-RegistryToolExecution"
  alarm_description   = "Suspicious registry tool execution detected"
  metric_name         = "RegistryToolExecution"
  namespace           = "Security/T1112"
  statistic           = "Sum"
  period              = 600
  evaluation_periods  = 1
  threshold           = 2
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}

# Step 3: Monitor critical registry modifications via reg.exe
resource "aws_cloudwatch_log_metric_filter" "critical_reg_mods" {
  name           = "critical-reg-tool-modifications"
  log_group_name = var.cloudwatch_log_group
  pattern        = "[time, instance, process, command=\"*DisableAntiSpyware*\" || command=\"*UseLogonCredential*\" || command=\"*EnableLUA*\"]"

  metric_transformation {
    name      = "CriticalRegToolMods"
    namespace = "Security/T1112"
    value     = "1"
  }
}

# Step 4: SNS topic policy
data "aws_caller_identity" "current" {}

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
}""",
                alert_severity="high",
                alert_title="Registry Tool Execution Detected",
                alert_description_template=(
                    "Suspicious registry tool execution detected on instance {instance_id}. "
                    "Process: {process_name}. Command: {command_line}. "
                    "Parent process: {parent_process_name}. Investigate for malicious intent."
                ),
                investigation_steps=[
                    "Review the full command line to identify what registry changes were attempted",
                    "Identify the parent process that launched the registry tool",
                    "Check if the execution was part of authorised administrative work",
                    "Review Windows Event ID 4688 (Process Creation) for execution context",
                    "Examine the user account that ran the registry command",
                    "Check for registry import files (.reg) and review their contents",
                    "Look for other registry modifications around the same time",
                    "Search for indicators of automated or scripted execution",
                ],
                containment_actions=[
                    "Terminate the registry tool process if still running",
                    "Revert unauthorised registry changes using Group Policy or backup",
                    "Delete any malicious .reg import files from the file system",
                    "Disable the user account if unauthorised activity is confirmed",
                    "Block reg.exe execution for non-administrative users via AppLocker",
                    "Re-enable disabled security features (Windows Defender, UAC)",
                    "Review and remove any malicious persistence mechanisms",
                    "Scan the instance with updated endpoint protection",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist authorised administrative accounts and scripts; baseline normal registry tool usage patterns",
            detection_coverage="85% - excellent coverage for command-line registry tool usage",
            evasion_considerations="Attackers may rename tools, use API calls directly, or leverage WMI for registry changes",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1.5 hours",
            estimated_monthly_cost="$5-15 depending on log volume",
            prerequisites=[
                "Process creation logging enabled (Event ID 4688)",
                "Command-line auditing enabled",
                "CloudWatch Agent configured to forward process logs",
            ],
        ),
    ],
    recommended_order=[
        "t1112-registry-events",
        "t1112-guardduty-runtime",
        "t1112-powershell-registry",
        "t1112-registry-tools",
        "t1112-gcp-registry",
    ],
    total_effort_hours=9.5,
    coverage_improvement="+30% improvement for Defence Evasion tactic",
)
