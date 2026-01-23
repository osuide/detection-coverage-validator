"""
T1055 - Process Injection

Adversaries inject arbitrary code into the address space of a separate live process
to evade process-based defences, elevate privileges, and mask malicious execution.

IMPORTANT DETECTION LIMITATIONS:
Process injection is an IN-MEMORY, OS-LEVEL technique. Direct detection requires:
- Endpoint Detection and Response (EDR) with kernel-level visibility
- GuardDuty Runtime Monitoring (uses eBPF agent for behavioural detection)
- OS-level audit logging (auditd with syscall monitoring)

Cloud-native APIs (CloudTrail, EventBridge) CANNOT see:
- Memory manipulation (VirtualAllocEx, WriteProcessMemory, mmap)
- Process memory access (/proc/pid/mem, ptrace)
- Library injection (CreateRemoteThread, LD_PRELOAD)

The strategies below provide:
- GuardDuty Runtime Monitoring: Behavioural detection via managed eBPF agent (~60% coverage)
- CloudWatch/Cloud Logging: Requires OS-level auditd configuration (~40% coverage)
- Without endpoint agents or auditd: <10% coverage (limited to post-compromise indicators)

For comprehensive protection, deploy GuardDuty Runtime Monitoring or third-party EDR
(CrowdStrike, SentinelOne, Carbon Black, Microsoft Defender for Endpoint).
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
    technique_id="T1055",
    technique_name="Process Injection",
    tactic_ids=["TA0005", "TA0004"],
    mitre_url="https://attack.mitre.org/techniques/T1055/",
    threat_context=ThreatContext(
        description=(
            "Adversaries inject arbitrary code into the address space of a separate live process. "
            "Process injection enables attackers to evade process-based defences, elevate privileges, "
            "and mask malicious execution under legitimate processes. Advanced implementations may employ "
            "multiple injections with inter-process communication mechanisms like named pipes. In cloud "
            "environments, this occurs in compromised EC2 instances, container hosts, or workloads with "
            "excessive privileges."
        ),
        attacker_goal="Execute malicious code within legitimate processes to evade detection and maintain persistence",
        why_technique=[
            "Masks malicious activity under trusted processes",
            "Evades process-based security monitoring",
            "Gains access to process memory and resources",
            "Potentially elevates privileges",
            "Bypasses application control mechanisms",
            "Enables credential theft from process memory",
            "Difficult to detect without advanced monitoring",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=9,
        severity_reasoning=(
            "Process injection is a sophisticated technique that enables attackers to evade detection, "
            "escalate privileges, and steal credentials from memory. It is commonly used by advanced "
            "persistent threats and ransomware groups. The technique is difficult to detect without "
            "specialised monitoring, making it a high-severity threat requiring immediate investigation."
        ),
        business_impact=[
            "Credential theft from process memory",
            "Privilege escalation to SYSTEM/root",
            "Evasion of endpoint detection solutions",
            "Data exfiltration through legitimate processes",
            "Persistence mechanisms difficult to remove",
            "Lateral movement using stolen credentials",
            "Ransomware deployment masked as legitimate activity",
        ],
        typical_attack_phase="privilege_escalation",
        often_precedes=["T1003", "T1078", "T1095", "T1071"],
        often_follows=["T1190", "T1133", "T1078.004", "T1552.005"],
    ),
    detection_strategies=[
        # AWS Strategy 1: GuardDuty Runtime Monitoring
        DetectionStrategy(
            strategy_id="t1055-guardduty-runtime",
            name="AWS GuardDuty Runtime Monitoring for Process Injection",
            description=(
                "GuardDuty Runtime Monitoring detects suspicious process behaviour including "
                "memory manipulation, library injection, and abnormal process spawning patterns "
                "on EC2 instances and ECS/EKS containers."
            ),
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                # GuardDuty Runtime Monitoring has SPECIFIC process injection finding types
                # that detect memory manipulation, ptrace, and virtual memory writes.
                guardduty_finding_types=[
                    # Primary process injection detections
                    "DefenseEvasion:Runtime/ProcessInjection.Proc",
                    "DefenseEvasion:Runtime/ProcessInjection.Ptrace",
                    "DefenseEvasion:Runtime/ProcessInjection.VirtualMemoryWrite",
                    # Related behavioural indicators
                    "Execution:Runtime/NewLibraryLoaded",
                    "Execution:Runtime/NewBinaryExecuted",
                    "Execution:Runtime/SuspiciousTool",
                    "DefenseEvasion:Runtime/FilelessExecution",
                    "PrivilegeEscalation:Runtime/RuncContainerEscape",
                ],
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: |
  GuardDuty Runtime Monitoring for process injection detection (T1055)

  IMPORTANT: Runtime Monitoring requires GuardDuty security agent deployment:
  - EC2: SSM agent auto-deploys GuardDuty agent (verify via SSM Fleet Manager)
  - EKS: GuardDuty addon auto-managed (verify: kubectl get pods -n amazon-guardduty)
  - ECS Fargate: Auto-managed (verify via GuardDuty console > Runtime Monitoring > Coverage)

  Coverage is NOT guaranteed just by enabling the feature - verify agent status!
  Unsupported: EKS on Fargate, Windows containers, non-SSM managed EC2 instances

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
          AdditionalConfiguration:
            # Alphabetical order to prevent drift
            - Name: EC2_AGENT_MANAGEMENT
              Status: ENABLED
            - Name: ECS_FARGATE_AGENT_MANAGEMENT
              Status: ENABLED
            - Name: EKS_ADDON_MANAGEMENT
              Status: ENABLED

  # Step 2: Create SNS topic for critical alerts
  ProcessInjectionAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: Process Injection Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 3: Route process injection findings to alerts
  # Pattern scoped to ONLY process injection findings to avoid alert fatigue
  # Finding types: ProcessInjection.Proc, ProcessInjection.Ptrace, ProcessInjection.VirtualMemoryWrite
  ProcessInjectionRule:
    Type: AWS::Events::Rule
    Properties:
      Name: T1055-ProcessInjectionDetection
      Description: Alert on GuardDuty process injection findings (severity >= 4)
      EventPattern:
        source:
          - aws.guardduty
        detail-type:
          - GuardDuty Finding
        detail:
          type:
            - prefix: "DefenseEvasion:Runtime/ProcessInjection.Proc"
          severity:
            - numeric:
                - ">="
                - 4
      State: ENABLED
      Targets:
        - Id: SNSTarget
          Arn: !Ref ProcessInjectionAlertTopic

  # SNS topic policy with aws:SourceArn condition for least privilege
  SNSTopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref ProcessInjectionAlertTopic
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Sid: AllowEventBridgeRule
            Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref ProcessInjectionAlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn: !GetAtt ProcessInjectionRule.Arn

Outputs:
  GuardDutyDetectorId:
    Description: GuardDuty detector ID
    Value: !Ref GuardDutyDetector
  AlertTopicArn:
    Description: SNS topic for alerts
    Value: !Ref ProcessInjectionAlertTopic
  EventRuleArn:
    Description: EventBridge rule ARN
    Value: !GetAtt ProcessInjectionRule.Arn""",
                terraform_template="""# GuardDuty Runtime Monitoring for process injection detection
#
# IMPORTANT: Runtime Monitoring requires GuardDuty security agent deployment:
# - EC2: SSM agent auto-deploys GuardDuty agent (verify via SSM Fleet Manager)
# - EKS: GuardDuty addon auto-managed (verify: kubectl get pods -n amazon-guardduty)
# - ECS Fargate: Auto-managed (verify via GuardDuty console > Runtime Monitoring > Coverage)
#
# Coverage is NOT guaranteed just by enabling the feature - verify agent status!
# Unsupported: EKS on Fargate, Windows containers, non-SSM managed EC2 instances

variable "alert_email" {
  description = "Email address for security alerts"
  type        = string
}

variable "aws_account_id" {
  description = "AWS account ID for policy conditions"
  type        = string
}

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "eu-west-2"
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

# Enable Runtime Monitoring feature
# NOTE: Keep additional_configuration blocks in alphabetical order to prevent
# Terraform provider drift issues (known issue with some AWS provider versions)
resource "aws_guardduty_detector_feature" "runtime_monitoring" {
  detector_id = aws_guardduty_detector.main.id
  name        = "RUNTIME_MONITORING"
  status      = "ENABLED"

  additional_configuration {
    name   = "EC2_AGENT_MANAGEMENT"
    status = "ENABLED"
  }

  additional_configuration {
    name   = "ECS_FARGATE_AGENT_MANAGEMENT"
    status = "ENABLED"
  }

  additional_configuration {
    name   = "EKS_ADDON_MANAGEMENT"
    status = "ENABLED"
  }

  lifecycle {
    # Prevent replacement due to provider ordering changes
    create_before_destroy = true
  }
}

# Step 2: Create SNS topic for critical alerts
resource "aws_sns_topic" "process_injection_alerts" {
  name              = "guardduty-process-injection-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name      = "Process Injection Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.process_injection_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 3: Route process injection findings to alerts
# Pattern scoped to ONLY process injection findings to avoid alert fatigue
# Finding types: ProcessInjection.Proc, ProcessInjection.Ptrace, ProcessInjection.VirtualMemoryWrite
resource "aws_cloudwatch_event_rule" "process_injection" {
  name        = "guardduty-process-injection-detection"
  description = "Alert on GuardDuty process injection findings (T1055)"

  event_pattern = jsonencode({
    source        = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    detail = {
      type = [
        { prefix = "DefenseEvasion:Runtime/ProcessInjection.Proc" }
      ]
      # Severity >= 4 (MEDIUM or above) to filter noise
      severity = [
        { numeric = [">=", 4] }
      ]
    }
  })
}

# Dead Letter Queue for failed event deliveries
resource "aws_sqs_queue" "dlq" {
  name                      = "guardduty-process-injection-dlq"
  message_retention_seconds = 1209600  # 14 days
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
      values   = [aws_cloudwatch_event_rule.process_injection.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "event_dlq" {
  queue_url = aws_sqs_queue.dlq.url
  policy    = data.aws_iam_policy_document.eventbridge_dlq_policy.json
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.process_injection.name
  target_id = "SNSTarget"
  arn       = aws_sns_topic.process_injection_alerts.arn

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

# SNS topic policy with aws:SourceArn condition for least privilege
data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.process_injection_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowEventBridgeRule"
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.process_injection_alerts.arn
      Condition = {
        ArnEquals = {
          "aws:SourceArn" = "arn:aws:events:$${var.aws_region}:$${var.aws_account_id}:rule/${aws_cloudwatch_event_rule.process_injection.name}"
        }
      }
    }]
  })
}

output "guardduty_detector_id" {
  description = "GuardDuty detector ID"
  value       = aws_guardduty_detector.main.id
}

output "alert_topic_arn" {
  description = "SNS topic for alerts"
  value       = aws_sns_topic.process_injection_alerts.arn
}

output "event_rule_arn" {
  description = "EventBridge rule ARN"
  value       = aws_cloudwatch_event_rule.process_injection.arn
}""",
                alert_severity="critical",
                alert_title="GuardDuty: Process Injection Detected",
                alert_description_template=(
                    "GuardDuty detected process injection activity: {finding_type}. "
                    "Resource: {resource}. Principal: {principal}. "
                    "This indicates advanced evasion techniques requiring immediate investigation."
                ),
                investigation_steps=[
                    "Identify the affected EC2 instance, container, or EKS pod",
                    "Review the process tree and parent-child relationships",
                    "Examine memory dumps for injected code (if possible)",
                    "Check for recently loaded libraries or DLLs",
                    "Analyse network connections from the affected process",
                    "Review CloudTrail for suspicious API calls before injection",
                    "Identify the initial access vector (compromised credentials, exploit, etc.)",
                    "Search for similar behaviour across other instances",
                ],
                containment_actions=[
                    "Immediately isolate the affected instance/container",
                    "Terminate the malicious process and injected code",
                    "Capture memory dump for forensic analysis",
                    "Rotate all credentials accessible from the instance",
                    "Review and revoke IAM roles/instance profiles",
                    "Enable advanced threat protection on remaining resources",
                    "Deploy security patches to prevent re-exploitation",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist legitimate software that uses code injection (debuggers, monitoring tools). Exclude authorised DevOps processes.",
            detection_coverage="60% - behavioural detection via eBPF agent. Cannot detect all injection techniques; requires Runtime Monitoring agent deployed.",
            evasion_considerations="Advanced attackers may use novel injection techniques not yet detected by runtime analysis. Linux-specific techniques (ptrace, /proc/mem) may have limited coverage.",
            implementation_effort=EffortLevel.LOW,
            implementation_time="45 minutes",
            estimated_monthly_cost="$4.60 per EC2 instance + $2 per ECS/EKS task (Runtime Monitoring pricing)",
            prerequisites=[
                "AWS account with GuardDuty access",
                "EC2/ECS/EKS workloads",
                "SSM agent for EC2 automated deployment",
            ],
        ),
        # AWS Strategy 2: CloudWatch Logs Analysis for Suspicious Process Behaviour
        DetectionStrategy(
            strategy_id="t1055-cloudwatch-process-monitoring",
            name="CloudWatch Logs Process Injection Indicators",
            description=(
                "Monitor system logs for API call sequences indicative of process injection: "
                "VirtualAllocEx, WriteProcessMemory, CreateRemoteThread on Windows; "
                "ptrace, mmap, /proc/pid/mem access on Linux systems."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query=r"""fields @timestamp, @message, host, process_name, syscall
| filter @message like /ptrace|process_vm_writev|process_vm_readv|/
   or @message like /VirtualAllocEx|WriteProcessMemory|CreateRemoteThread/
   or @message like /\/proc\/\d+\/mem|\/proc\/\d+\/maps/
   or @message like /PTRACE_POKETEXT|PTRACE_POKEDATA|PTRACE_SETREGS/
| parse @message /(?<injector_process>\S+).*(?<target_pid>\d+)/
| sort @timestamp desc
| limit 100""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: CloudWatch-based process injection detection via system logs

Parameters:
  SystemLogGroup:
    Type: String
    Description: CloudWatch log group for system/audit logs (e.g., /var/log/audit/audit.log)
  AlertEmail:
    Type: String
    Description: Email address for security alerts

Resources:
  # Step 1: Create metric filter for process injection indicators
  ProcessInjectionMetricFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref SystemLogGroup
      FilterPattern: '[timestamp, msg_type, syscall, success, ...] (msg_type=SYSCALL && (syscall=ptrace || syscall=process_vm_writev || syscall=process_vm_readv))'
      MetricTransformations:
        - MetricName: ProcessInjectionIndicators
          MetricNamespace: Security/T1055
          MetricValue: "1"
          DefaultValue: 0

  # Step 2: Create CloudWatch alarm
  ProcessInjectionAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1055-ProcessInjectionDetected
      AlarmDescription: Detected suspicious process injection activity
      MetricName: ProcessInjectionIndicators
      Namespace: Security/T1055
      Statistic: Sum
      Period: 300
      Threshold: 1
      ComparisonOperator: GreaterThanOrEqualToThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref AlertTopic

  # Step 3: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: Process Injection Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref AlertTopic
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Sid: AllowCloudWatchAlarms
            Effect: Allow
            Principal:
              Service: cloudwatch.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic

Outputs:
  AlarmName:
    Description: CloudWatch alarm name
    Value: !Ref ProcessInjectionAlarm""",
                terraform_template="""# CloudWatch-based process injection detection via system logs

variable "system_log_group" {
  description = "CloudWatch log group for system/audit logs"
  type        = string
}

variable "alert_email" {
  description = "Email address for security alerts"
  type        = string
}

# Step 1: Create metric filter for process injection indicators
resource "aws_cloudwatch_log_metric_filter" "process_injection" {
  name           = "process-injection-indicators"
  log_group_name = var.system_log_group
  pattern        = "[timestamp, msg_type, syscall, success, ...] (msg_type=SYSCALL && (syscall=ptrace || syscall=process_vm_writev || syscall=process_vm_readv))"

  metric_transformation {
    name          = "ProcessInjectionIndicators"
    namespace     = "Security/T1055"
    value         = "1"
    default_value = 0
  }
}

# Step 2: Create CloudWatch alarm
resource "aws_cloudwatch_metric_alarm" "process_injection" {
  alarm_name          = "process-injection-detected"
  alarm_description   = "Detected suspicious process injection activity"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "ProcessInjectionIndicators"
  namespace           = "Security/T1055"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}

# Step 3: SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name              = "process-injection-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name      = "Process Injection Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "alerts" {
  arn = aws_sns_topic.alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
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

output "alarm_name" {
  description = "CloudWatch alarm name"
  value       = aws_cloudwatch_metric_alarm.process_injection.alarm_name
}""",
                alert_severity="critical",
                alert_title="Process Injection Indicators Detected",
                alert_description_template=(
                    "Suspicious process injection behaviour detected on instance {instance_id}. "
                    "Injector process: {injector_process}. Target PID: {target_pid}. "
                    "Syscall: {syscall}."
                ),
                investigation_steps=[
                    "Review audit logs for the specific ptrace/injection syscalls",
                    "Identify the source and target processes",
                    "Check if the injector process is legitimate or malicious",
                    "Examine the command line arguments of both processes",
                    "Review network connections from the target process",
                    "Check for recently modified binaries or libraries",
                    "Search for persistence mechanisms (cron, systemd, startup scripts)",
                ],
                containment_actions=[
                    "Kill the malicious injector process",
                    "Terminate the compromised target process",
                    "Enable kernel security modules (SELinux, AppArmor)",
                    "Restrict ptrace capabilities via sysctl (kernel.yama.ptrace_scope=3)",
                    "Deploy intrusion detection tools (OSSEC, Wazuh)",
                    "Review and harden instance security groups",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude debuggers (gdb, lldb), monitoring tools (strace, sysdig), and authorised DevOps processes. Requires Linux audit logging (auditd) configured.",
            detection_coverage="60% - requires auditd configuration. Covers Linux syscall-based injection only.",
            evasion_considerations="Attackers may disable auditd or use alternative injection methods (LD_PRELOAD, /proc/self/mem). Limited Windows coverage without Sysmon.",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$10-30 (depends on log volume)",
            prerequisites=[
                "Linux audit logging (auditd) enabled",
                "CloudWatch agent configured",
                "System logs forwarded to CloudWatch",
            ],
        ),
        # GCP Strategy: Cloud Logging for Process Injection
        DetectionStrategy(
            strategy_id="t1055-gcp-logging-process-injection",
            name="GCP Cloud Logging Process Injection Detection",
            description=(
                "Monitor GCP Cloud Logging for suspicious process behaviour on GCE instances "
                "and GKE containers, including ptrace syscalls, memory manipulation, and "
                "abnormal library loading patterns."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_instance" OR resource.type="k8s_container"
(jsonPayload.syscall="ptrace" OR
 jsonPayload.syscall="process_vm_writev" OR
 jsonPayload.syscall="process_vm_readv" OR
 textPayload=~"PTRACE_POKETEXT|PTRACE_POKEDATA|PTRACE_SETREGS" OR
 textPayload=~"/proc/[0-9]+/mem")
severity >= WARNING""",
                gcp_terraform_template="""# GCP: Process injection detection via Cloud Logging

variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "alert_email" {
  description = "Email address for security alerts"
  type        = string
}

# Step 1: Create log-based metric for process injection
resource "google_logging_metric" "process_injection" {
  project = var.project_id
  name    = "process-injection-indicators"
  filter  = <<-EOT
    resource.type="gce_instance" OR resource.type="k8s_container"
    (jsonPayload.syscall="ptrace" OR
     jsonPayload.syscall="process_vm_writev" OR
     jsonPayload.syscall="process_vm_readv" OR
     textPayload=~"PTRACE_POKETEXT|PTRACE_POKEDATA|PTRACE_SETREGS" OR
     textPayload=~"/proc/[0-9]+/mem")
    severity >= WARNING
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "instance_id"
      value_type  = "STRING"
      description = "GCE instance ID"
    }
    labels {
      key         = "syscall"
      value_type  = "STRING"
      description = "System call used"
    }
  }

  label_extractors = {
    "instance_id" = "EXTRACT(resource.labels.instance_id)"
    "syscall"     = "EXTRACT(jsonPayload.syscall)"
  }
}

# Step 2: Create notification channel
resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "Process Injection Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 3: Create alert policy
resource "google_monitoring_alert_policy" "process_injection" {
  project      = var.project_id
  display_name = "Process Injection Detection"
  combiner     = "OR"

  conditions {
    display_name = "Process injection indicators detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.process_injection.name}\" AND resource.type=\"gce_instance\""
      duration        = "60s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      aggregations {
        alignment_period   = "60s"
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

  documentation {
    content   = <<-EOT
      # Process Injection Detected (T1055)

      Suspicious process injection activity detected via syscalls like ptrace or /proc/pid/mem access.

      ## Investigation Steps:
      1. Identify the source and target processes
      2. Review audit logs for detailed syscall information
      3. Check for malicious binaries or libraries
      4. Examine network connections from compromised process

      ## Containment:
      - Terminate malicious processes
      - Enable kernel security modules (SELinux, AppArmor)
      - Restrict ptrace capabilities
    EOT
    mime_type = "text/markdown"
  }
}

output "log_metric_name" {
  description = "Log-based metric name"
  value       = google_logging_metric.process_injection.name
}

output "alert_policy_id" {
  description = "Alert policy ID"
  value       = google_monitoring_alert_policy.process_injection.id
}""",
                alert_severity="critical",
                alert_title="GCP: Process Injection Detected",
                alert_description_template=(
                    "Process injection indicators detected on GCE instance {instance_id}. "
                    "Syscall: {syscall}. Review audit logs immediately."
                ),
                investigation_steps=[
                    "Identify the GCE instance or GKE pod affected",
                    "Review Cloud Audit Logs for the specific syscalls",
                    "Examine the process tree and relationships",
                    "Check for recently loaded shared libraries (.so files)",
                    "Review VPC Flow Logs for suspicious network activity",
                    "Identify initial access vector (SSH keys, service accounts, vulnerabilities)",
                    "Search for similar patterns across other instances",
                ],
                containment_actions=[
                    "Terminate the compromised instance or pod",
                    "Create forensic snapshot before termination",
                    "Rotate service account keys and credentials",
                    "Enable OS Login and disable direct SSH access",
                    "Deploy Security Command Center Premium for advanced threat detection",
                    "Configure shielded VMs for future instances",
                    "Review and tighten firewall rules",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude authorised debuggers, monitoring agents (Cloud Ops Agent), and DevOps tools. Requires audit logging enabled on GCE instances.",
            detection_coverage="60% - requires OS-level audit logging. Primarily Linux-focused.",
            evasion_considerations="Attackers may disable audit logging or use novel injection techniques. Requires proper kernel audit configuration.",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1.5 hours",
            estimated_monthly_cost="$5-20 (depends on log ingestion volume)",
            prerequisites=[
                "GCE/GKE audit logging enabled",
                "Cloud Logging configured",
                "OS-level audit daemon (auditd) installed",
            ],
        ),
        # AWS Strategy 3: Security Hub Custom Findings
        DetectionStrategy(
            strategy_id="t1055-securityhub-aggregation",
            name="Security Hub Process Injection Finding Aggregation",
            description=(
                "Aggregate and correlate process injection indicators from multiple sources "
                "(GuardDuty, Inspector, third-party EDR) into Security Hub for centralised "
                "visibility and automated response."
            ),
            detection_type=DetectionType.SECURITY_HUB,
            aws_service="securityhub",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Security Hub aggregation for process injection findings

Parameters:
  AlertEmail:
    Type: String
    Description: Email address for critical findings

Resources:
  # Step 1: Enable Security Hub
  SecurityHub:
    Type: AWS::SecurityHub::Hub

  # Step 2: Create custom insight for process injection
  ProcessInjectionInsight:
    Type: AWS::SecurityHub::Insight
    Properties:
      Filters:
        ComplianceStatus:
          - Value: FAILED
            Comparison: EQUALS
        Title:
          - Value: "process injection"
            Comparison: CONTAINS
        RecordState:
          - Value: ACTIVE
            Comparison: EQUALS
      GroupByAttribute: ResourceId
      Name: T1055-ProcessInjectionFindings

  # Step 3: EventBridge rule for critical findings
  CriticalFindingsRule:
    Type: AWS::Events::Rule
    Properties:
      Name: T1055-SecurityHubCriticalFindings
      Description: Route critical process injection findings to SNS
      EventPattern:
        source: [aws.securityhub]
        detail-type: [Security Hub Findings - Imported]
        detail:
          findings:
            Title:
              - prefix: "process injection"
              - prefix: "Process Injection"
            Severity:
              Label: [CRITICAL, HIGH]
            RecordState: [ACTIVE]
      State: ENABLED
      Targets:
        - Id: SNSTarget
          Arn: !Ref AlertTopic

  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: Security Hub Critical Findings
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # SNS topic policy with aws:SourceArn condition for least privilege
  SNSTopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref AlertTopic
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Sid: AllowEventBridgeRule
            Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn: !GetAtt CriticalFindingsRule.Arn

Outputs:
  SecurityHubArn:
    Description: Security Hub ARN
    Value: !Ref SecurityHub
  InsightArn:
    Description: Process injection insight ARN
    Value: !GetAtt ProcessInjectionInsight.InsightArn
  EventRuleArn:
    Description: EventBridge rule ARN
    Value: !GetAtt CriticalFindingsRule.Arn""",
                terraform_template="""# Security Hub aggregation for process injection findings

variable "alert_email" {
  description = "Email address for critical findings"
  type        = string
}

# Step 1: Enable Security Hub
resource "aws_securityhub_account" "main" {}

resource "aws_securityhub_standards_subscription" "cis" {
  standards_arn = "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0"
  depends_on    = [aws_securityhub_account.main]
}

# Step 2: Create custom insight for process injection
resource "aws_securityhub_insight" "process_injection" {
  filters {
    compliance_status {
      comparison = "EQUALS"
      value      = "FAILED"
    }

    title {
      comparison = "CONTAINS"
      value      = "process injection"
    }

    record_state {
      comparison = "EQUALS"
      value      = "ACTIVE"
    }
  }

  group_by_attribute = "ResourceId"
  name               = "T1055-ProcessInjectionFindings"
}

# Step 3: EventBridge rule for critical findings
resource "aws_cloudwatch_event_rule" "critical_findings" {
  name        = "securityhub-critical-findings"
  description = "Route critical process injection findings to SNS"

  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Imported"]
    detail = {
      findings = {
        Title = [
          { prefix = "process injection" },
          { prefix = "Process Injection" }
        ]
        Severity = {
          Label = ["CRITICAL", "HIGH"]
        }
        RecordState = ["ACTIVE"]
      }
    }
  })
}

# Dead Letter Queue for failed event deliveries
resource "aws_sqs_queue" "dlq" {
  name                      = "securityhub-critical-alerts-dlq"
  message_retention_seconds = 1209600  # 14 days
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.critical_findings.name
  target_id = "SNSTarget"
  arn       = aws_sns_topic.alerts.arn

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

resource "aws_sns_topic" "alerts" {
  name              = "securityhub-critical-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name      = "Security Hub Critical Findings"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

data "aws_caller_identity" "current" {}

# SNS topic policy with aws:SourceArn and AWS:SourceAccount for least privilege
resource "aws_sns_topic_policy" "alerts" {
  arn = aws_sns_topic.alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowEventBridgeRule"
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.critical_findings.arn
        }
      }
    }]
  })
}

output "securityhub_arn" {
  description = "Security Hub ARN"
  value       = aws_securityhub_account.main.arn
}

output "insight_arn" {
  description = "Process injection insight ARN"
  value       = aws_securityhub_insight.process_injection.arn
}

output "event_rule_arn" {
  description = "EventBridge rule ARN"
  value       = aws_cloudwatch_event_rule.critical_findings.arn
}""",
                alert_severity="critical",
                alert_title="Security Hub: Process Injection Finding",
                alert_description_template=(
                    "Security Hub aggregated process injection finding. "
                    "Resource: {ResourceId}. Source: {ProductName}. "
                    "Review Security Hub console for full details."
                ),
                investigation_steps=[
                    "Review the Security Hub finding details",
                    "Check all associated resources and accounts",
                    "Correlate with GuardDuty, Inspector, and CloudTrail logs",
                    "Identify the detection source (native AWS or third-party EDR)",
                    "Review compliance status and remediation recommendations",
                    "Check for related findings in the same time window",
                ],
                containment_actions=[
                    "Follow remediation guidance from Security Hub",
                    "Enable automated response via Security Hub custom actions",
                    "Quarantine affected resources using Systems Manager",
                    "Update security standards and compliance frameworks",
                    "Deploy compensating controls via AWS Config",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Security Hub aggregates findings from multiple sources. Tune individual detection mechanisms (GuardDuty, Inspector) to reduce false positives.",
            detection_coverage="70% - requires GuardDuty Runtime Monitoring or endpoint EDR deployment.",
            evasion_considerations="Depends on underlying detection sources. No inherent evasion beyond those sources.",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$0.0010 per finding + underlying service costs",
            prerequisites=[
                "Security Hub enabled",
                "GuardDuty enabled",
                "Optional: Third-party EDR integration",
            ],
        ),
        # Azure Strategy: Process Injection
        DetectionStrategy(
            strategy_id="t1055-azure",
            name="Azure Process Injection Detection",
            description=(
                "Azure detection for Process Injection. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.SENTINEL_RULE,
            aws_service="n/a",
            azure_service="sentinel",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                sentinel_rule_query="""// Sentinel Analytics Rule: Process Injection
// MITRE ATT&CK: T1055
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
                azure_terraform_template="""# Azure Detection for Process Injection
# MITRE ATT&CK: T1055

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
  name                = "process-injection-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "SecAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Scheduled Query Rule for detection
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "detection" {
  name                = "process-injection-detection"
  resource_group_name = var.resource_group_name
  location            = "uksouth"

  evaluation_frequency = "PT5M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 2

  criteria {
    query = <<-QUERY
// Sentinel Analytics Rule: Process Injection
// MITRE ATT&CK: T1055
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

  description = "Detects Process Injection (T1055) activity in Azure environment"
  display_name = "Process Injection Detection"
  enabled      = true

  tags = {
    "mitre-technique" = "T1055"
    "detection-type"  = "security"
  }
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.detection.id
}""",
                alert_severity="high",
                alert_title="Azure: Process Injection Detected",
                alert_description_template=(
                    "Process Injection activity detected. "
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
            detection_coverage="30% - only monitors Azure cloud operations, cannot detect endpoint process memory operations",
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
        "t1055-guardduty-runtime",
        "t1055-securityhub-aggregation",
        "t1055-cloudwatch-process-monitoring",
        "t1055-gcp-logging-process-injection",
    ],
    total_effort_hours=5.0,
    coverage_improvement="+35% improvement for Defence Evasion and Privilege Escalation tactics",
)
