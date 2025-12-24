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
    Campaign,
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
        known_threat_actors=[
            "APT32",
            "APT37",
            "APT38",
            "APT41",
            "Cobalt Group",
            "Gamaredon Group",
            "Kimsuky",
            "Lazarus Group",
            "PLATINUM",
            "Silence",
            "BlackByte",
            "REvil",
            "Ryuk",
            "Sandworm Team",
        ],
        recent_campaigns=[
            Campaign(
                name="2015 Ukraine Electric Power Attack",
                year=2015,
                description="Sandworm Team loaded BlackEnergy into svchost.exe for command and control operations",
                reference_url="https://attack.mitre.org/campaigns/C0028/",
            ),
            Campaign(
                name="3CX Supply Chain Attack",
                year=2023,
                description="AppleJeus injected C2 modules into Chrome, Firefox, and Edge browser processes",
                reference_url="https://attack.mitre.org/campaigns/C0057/",
            ),
            Campaign(
                name="ArcaneDoor",
                year=2024,
                description="Injected malicious code into AAA and Crash Dump processes on Cisco ASA devices",
                reference_url="https://attack.mitre.org/campaigns/C0046/",
            ),
            Campaign(
                name="Operation Wocao",
                year=2019,
                description="Process injection used for code execution and privilege escalation",
                reference_url="https://attack.mitre.org/campaigns/C0014/",
            ),
        ],
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
                # NOTE: GuardDuty Runtime Monitoring finding types are behavioural indicators.
                # There are NO specific "ProcessInjection" finding types - detection is via
                # suspicious process behaviour patterns (new binaries, fileless execution).
                guardduty_finding_types=[
                    "Execution:Runtime/NewLibraryLoaded",
                    "Execution:Runtime/NewBinaryExecuted",
                    "Execution:Runtime/SuspiciousTool",
                    "DefenseEvasion:Runtime/FilelessExecution",
                    "DefenseEvasion:Runtime/SuspiciousCommand",
                    "PrivilegeEscalation:Runtime/ContainerMountsHostFS",
                    "PrivilegeEscalation:Runtime/RuncContainerEscape",
                ],
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: GuardDuty Runtime Monitoring for process injection detection

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
            - Name: ECS_FARGATE_AGENT_MANAGEMENT
              Status: ENABLED
            - Name: EKS_ADDON_MANAGEMENT
              Status: ENABLED
            - Name: EC2_AGENT_MANAGEMENT
              Status: ENABLED

  # Step 2: Create SNS topic for critical alerts
  ProcessInjectionAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: Process Injection Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 3: Route process injection findings to alerts
  ProcessInjectionRule:
    Type: AWS::Events::Rule
    Properties:
      Name: T1055-ProcessInjectionDetection
      Description: Alert on GuardDuty process injection findings
      EventPattern:
        source: [aws.guardduty]
        detail:
          type:
            - prefix: "Execution:Runtime/"
            - prefix: "DefenseEvasion:Runtime/ProcessInjection"
            - prefix: "PrivilegeEscalation:Runtime/"
      State: ENABLED
      Targets:
        - Id: SNSTarget
          Arn: !Ref ProcessInjectionAlertTopic

  SNSTopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref ProcessInjectionAlertTopic]
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref ProcessInjectionAlertTopic

Outputs:
  GuardDutyDetectorId:
    Description: GuardDuty detector ID
    Value: !Ref GuardDutyDetector
  AlertTopicArn:
    Description: SNS topic for alerts
    Value: !Ref ProcessInjectionAlertTopic""",
                terraform_template="""# GuardDuty Runtime Monitoring for process injection detection

variable "alert_email" {
  description = "Email address for security alerts"
  type        = string
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
resource "aws_guardduty_detector_feature" "runtime_monitoring" {
  detector_id = aws_guardduty_detector.main.id
  name        = "RUNTIME_MONITORING"
  status      = "ENABLED"

  additional_configuration {
    name   = "ECS_FARGATE_AGENT_MANAGEMENT"
    status = "ENABLED"
  }

  additional_configuration {
    name   = "EKS_ADDON_MANAGEMENT"
    status = "ENABLED"
  }

  additional_configuration {
    name   = "EC2_AGENT_MANAGEMENT"
    status = "ENABLED"
  }
}

# Step 2: Create SNS topic for critical alerts
resource "aws_sns_topic" "process_injection_alerts" {
  name         = "guardduty-process-injection-alerts"
  display_name = "Process Injection Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.process_injection_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 3: Route process injection findings to alerts
resource "aws_cloudwatch_event_rule" "process_injection" {
  name        = "guardduty-process-injection-detection"
  description = "Alert on GuardDuty process injection findings"

  event_pattern = jsonencode({
    source = ["aws.guardduty"]
    detail = {
      type = [
        { prefix = "Execution:Runtime/" },
        { prefix = "DefenseEvasion:Runtime/ProcessInjection" },
        { prefix = "PrivilegeEscalation:Runtime/" }
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.process_injection.name
  target_id = "SNSTarget"
  arn       = aws_sns_topic.process_injection_alerts.arn
}

resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.process_injection_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.process_injection_alerts.arn
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
      DisplayName: Process Injection Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref AlertTopic]
      PolicyDocument:
        Statement:
          - Effect: Allow
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
  name         = "process-injection-alerts"
  display_name = "Process Injection Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_sns_topic_policy" "alerts" {
  arn = aws_sns_topic.alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "SNS:Publish"
      Resource  = aws_sns_topic.alerts.arn
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
resource "google_monitoring_notification_channel" "email" {
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

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "1800s"
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
      DisplayName: Security Hub Critical Findings
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  SNSTopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref AlertTopic]
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic

Outputs:
  SecurityHubArn:
    Description: Security Hub ARN
    Value: !Ref SecurityHub
  InsightArn:
    Description: Process injection insight ARN
    Value: !GetAtt ProcessInjectionInsight.InsightArn""",
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

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.critical_findings.name
  target_id = "SNSTarget"
  arn       = aws_sns_topic.alerts.arn
}

resource "aws_sns_topic" "alerts" {
  name         = "securityhub-critical-alerts"
  display_name = "Security Hub Critical Findings"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_sns_topic_policy" "alerts" {
  arn = aws_sns_topic.alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "SNS:Publish"
      Resource  = aws_sns_topic.alerts.arn
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
