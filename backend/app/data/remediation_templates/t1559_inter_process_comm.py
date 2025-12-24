"""
T1559 - Inter-Process Communication

Adversaries abuse inter-process communication (IPC) mechanisms to execute arbitrary
code or commands locally. Techniques include Windows COM/DDE, Linux pipes/sockets,
and macOS XPC services to facilitate execution whilst avoiding detection.

MITRE ATT&CK Reference: https://attack.mitre.org/techniques/T1559/
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
    technique_id="T1559",
    technique_name="Inter-Process Communication",
    tactic_ids=["TA0002"],  # Execution
    mitre_url="https://attack.mitre.org/techniques/T1559/",
    threat_context=ThreatContext(
        description=(
            "Adversaries abuse inter-process communication (IPC) mechanisms to execute arbitrary "
            "code or commands locally. The technique leverages OS-specific IPC features including "
            "Windows Dynamic Data Exchange (DDE) and Component Object Model (COM), Linux sockets "
            "and pipes, or macOS XPC services to facilitate execution. Common implementations include "
            "creating named pipes for inter-module messaging, using shared memory segments, and "
            "exploiting COM objects for code execution."
        ),
        attacker_goal="Execute arbitrary code through operating system IPC mechanisms to evade detection and maintain execution flow",
        why_technique=[
            "Appears as legitimate inter-process communication",
            "Evades traditional process-based detection",
            "Enables modular malware architecture",
            "Facilitates communication between malware components",
            "Bypasses application control policies",
            "Allows execution in the context of trusted processes",
            "Difficult to distinguish from normal operations",
        ],
        known_threat_actors=[],
        recent_campaigns=[
            Campaign(
                name="3CX Supply Chain Attack",
                year=2023,
                description="AppleJeus malware created Windows named pipes for inter-module messaging during the 3CX supply chain compromise",
                reference_url="https://attack.mitre.org/campaigns/C0057/",
            ),
            Campaign(
                name="Operation MidnightEclipse",
                year=2024,
                description="Unknown actors piped stdout to bash for execution in sophisticated cloud environment compromise",
                reference_url="https://attack.mitre.org/campaigns/C0048/",
            ),
            Campaign(
                name="Cyclops Blink Campaign",
                year=2022,
                description="Cyclops Blink malware created pipes enabling inter-process communication for modular malware execution",
                reference_url="https://attack.mitre.org/software/S0687/",
            ),
        ],
        prevalence="moderate",
        trend="increasing",
        severity_score=7,
        severity_reasoning=(
            "IPC abuse enables stealthy code execution that mimics legitimate system behaviour. "
            "Difficult to detect without comprehensive process and system call monitoring. "
            "Commonly used in advanced malware for modular architectures and supply chain attacks. "
            "In cloud environments, can facilitate container escape and cross-process exploitation."
        ),
        business_impact=[
            "Stealthy malware execution",
            "Evasion of security controls",
            "Modular malware deployment",
            "Inter-component communication for advanced threats",
            "Container and host compromise",
            "Supply chain attack facilitation",
            "Credential and data theft",
        ],
        typical_attack_phase="execution",
        often_precedes=["T1055", "T1003", "T1078", "T1071"],
        often_follows=["T1190", "T1566", "T1195", "T1204"],
    ),
    detection_strategies=[
        # AWS Strategy 1: Named Pipe and IPC Monitoring
        DetectionStrategy(
            strategy_id="t1559-aws-ipc-monitoring",
            name="AWS Named Pipe and IPC Creation Monitoring",
            description=(
                "Monitor system logs for creation and access of named pipes, UNIX domain sockets, "
                "and shared memory segments indicative of IPC abuse on EC2 instances and container hosts."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, @message, host, process_name, syscall, pipe_name
| filter @message like /mkfifo|mknod.*p|socketpair|shmget|shmat/
   or @message like /CreateNamedPipe|CreatePipe|CallNamedPipe/
   or @message like /\\\\.\\\\pipe\\\\/
| parse @message /(?<process>\\S+).*(?<ipc_object>\\S+pipe\\S+|\\S+shm\\S+)/
| filter process not in ["systemd", "dockerd", "containerd"]
| sort @timestamp desc
| limit 100""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Named pipe and IPC creation detection for T1559

Parameters:
  SystemLogGroup:
    Type: String
    Description: CloudWatch log group for system/audit logs
  AlertEmail:
    Type: String
    Description: Email address for security alerts

Resources:
  # Step 1: Create metric filter for IPC creation
  IPCCreationFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref SystemLogGroup
      FilterPattern: '[timestamp, msg_type, syscall, success, ...] (msg_type=SYSCALL && (syscall=mkfifo || syscall=mknod || syscall=socketpair || syscall=shmget || syscall=shmat))'
      MetricTransformations:
        - MetricName: IPCCreationEvents
          MetricNamespace: Security/T1559
          MetricValue: "1"
          DefaultValue: 0

  # Step 2: Create CloudWatch alarm
  IPCCreationAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1559-IPC-Abuse-Detected
      AlarmDescription: Suspicious IPC mechanism creation detected
      MetricName: IPCCreationEvents
      Namespace: Security/T1559
      Statistic: Sum
      Period: 300
      Threshold: 5
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching
      AlarmActions:
        - !Ref AlertTopic

  # Step 3: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: IPC Abuse Alerts
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
    Value: !Ref IPCCreationAlarm""",
                terraform_template="""# Named pipe and IPC creation detection for T1559

variable "system_log_group" {
  description = "CloudWatch log group for system/audit logs"
  type        = string
}

variable "alert_email" {
  description = "Email address for security alerts"
  type        = string
}

# Step 1: Create metric filter for IPC creation
resource "aws_cloudwatch_log_metric_filter" "ipc_creation" {
  name           = "ipc-creation-events"
  log_group_name = var.system_log_group
  pattern        = "[timestamp, msg_type, syscall, success, ...] (msg_type=SYSCALL && (syscall=mkfifo || syscall=mknod || syscall=socketpair || syscall=shmget || syscall=shmat))"

  metric_transformation {
    name          = "IPCCreationEvents"
    namespace     = "Security/T1559"
    value         = "1"
    default_value = 0
  }
}

# Step 2: Create CloudWatch alarm
resource "aws_cloudwatch_metric_alarm" "ipc_creation" {
  alarm_name          = "ipc-abuse-detected"
  alarm_description   = "Suspicious IPC mechanism creation detected"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "IPCCreationEvents"
  namespace           = "Security/T1559"
  period              = 300
  statistic           = "Sum"
  threshold           = 5
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

# Step 3: SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name         = "ipc-abuse-alerts"
  display_name = "IPC Abuse Alerts"
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
  value       = aws_cloudwatch_metric_alarm.ipc_creation.alarm_name
}""",
                alert_severity="high",
                alert_title="Suspicious IPC Mechanism Creation Detected",
                alert_description_template=(
                    "Suspicious IPC creation detected on instance {instance_id}. "
                    "Process: {process}. IPC object: {ipc_object}. "
                    "Syscall: {syscall}."
                ),
                investigation_steps=[
                    "Identify the process creating IPC mechanisms",
                    "Review the command line arguments and parent process",
                    "Check if the process is legitimate or unknown",
                    "Examine named pipe or socket paths for suspicious patterns",
                    "Review network connections from the process",
                    "Check for multiple processes communicating via the IPC object",
                    "Search for related persistence mechanisms",
                    "Review process creation timeline for correlation",
                ],
                containment_actions=[
                    "Terminate suspicious processes using IPC",
                    "Remove malicious named pipes and sockets",
                    "Clear shared memory segments (ipcrm)",
                    "Enable comprehensive audit logging for IPC syscalls",
                    "Implement SELinux/AppArmor policies restricting IPC",
                    "Deploy endpoint detection and response (EDR) tools",
                    "Review and harden instance security posture",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude legitimate system services (systemd, dockerd, containerd) and database processes that use IPC. Tune threshold based on normal baseline.",
            detection_coverage="65% - captures UNIX domain socket and named pipe creation. Requires audit logging for comprehensive coverage.",
            evasion_considerations="Attackers may use existing pipes/sockets, disable auditd, or implement IPC through standard file descriptors. Windows COM/DDE requires Sysmon.",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$10-25 (depends on log volume)",
            prerequisites=[
                "Linux audit logging (auditd) enabled",
                "CloudWatch agent configured",
                "System logs forwarded to CloudWatch",
            ],
        ),
        # AWS Strategy 2: GuardDuty Runtime Monitoring for IPC Abuse
        DetectionStrategy(
            strategy_id="t1559-guardduty-ipc",
            name="GuardDuty Runtime Monitoring for IPC Abuse",
            description=(
                "GuardDuty Runtime Monitoring detects suspicious inter-process communication "
                "patterns including anomalous pipe creation, shared memory access, and "
                "unusual process relationships on EC2 and container workloads."
            ),
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "Execution:Runtime/NewBinaryExecuted",
                    "DefenseEvasion:Runtime/FilelessExecution",
                    "Execution:Runtime/SuspiciousProcess",
                    "Execution:Runtime/AnomalousProcessCommunication",
                ],
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: GuardDuty Runtime Monitoring for IPC abuse detection

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

  # Step 2: Create SNS topic for alerts
  IPCAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: IPC Abuse Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 3: EventBridge rule for IPC-related findings
  IPCFindingsRule:
    Type: AWS::Events::Rule
    Properties:
      Name: T1559-IPC-Abuse-Detection
      Description: Alert on GuardDuty IPC abuse findings
      EventPattern:
        source: [aws.guardduty]
        detail:
          type:
            - prefix: "Execution:Runtime/"
            - prefix: "DefenseEvasion:Runtime/"
      State: ENABLED
      Targets:
        - Id: SNSTarget
          Arn: !Ref IPCAlertTopic

  SNSTopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref IPCAlertTopic]
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref IPCAlertTopic

Outputs:
  GuardDutyDetectorId:
    Description: GuardDuty detector ID
    Value: !Ref GuardDutyDetector""",
                terraform_template="""# GuardDuty Runtime Monitoring for IPC abuse detection

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

# Step 2: Create SNS topic for alerts
resource "aws_sns_topic" "ipc_alerts" {
  name         = "guardduty-ipc-abuse-alerts"
  display_name = "IPC Abuse Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.ipc_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 3: EventBridge rule for IPC-related findings
resource "aws_cloudwatch_event_rule" "ipc_findings" {
  name        = "guardduty-ipc-abuse-detection"
  description = "Alert on GuardDuty IPC abuse findings"

  event_pattern = jsonencode({
    source = ["aws.guardduty"]
    detail = {
      type = [
        { prefix = "Execution:Runtime/" },
        { prefix = "DefenseEvasion:Runtime/" }
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.ipc_findings.name
  target_id = "SNSTarget"
  arn       = aws_sns_topic.ipc_alerts.arn
}

resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.ipc_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "SNS:Publish"
      Resource  = aws_sns_topic.ipc_alerts.arn
    }]
  })
}

output "guardduty_detector_id" {
  description = "GuardDuty detector ID"
  value       = aws_guardduty_detector.main.id
}""",
                alert_severity="high",
                alert_title="GuardDuty: Suspicious IPC Activity Detected",
                alert_description_template=(
                    "GuardDuty detected suspicious inter-process communication: {finding_type}. "
                    "Resource: {resource}. Investigate process relationships immediately."
                ),
                investigation_steps=[
                    "Review GuardDuty finding details and evidence",
                    "Identify affected EC2 instance or container",
                    "Examine process tree and parent-child relationships",
                    "Check for anomalous pipe or socket creation",
                    "Review network connections from involved processes",
                    "Analyse command line arguments of communicating processes",
                    "Search for persistence mechanisms",
                    "Check CloudTrail for suspicious API activity",
                ],
                containment_actions=[
                    "Isolate affected instance or container",
                    "Terminate malicious processes",
                    "Remove suspicious IPC objects",
                    "Rotate credentials accessible from the resource",
                    "Enable enhanced monitoring and logging",
                    "Deploy endpoint protection tools",
                    "Review IAM roles and permissions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Minimal tuning required. GuardDuty uses ML baselines. Whitelist authorised DevOps processes if needed.",
            detection_coverage="80% - comprehensive runtime behaviour analysis on supported platforms",
            evasion_considerations="Advanced attackers may use legitimate IPC patterns. GuardDuty learns from baseline behaviour.",
            implementation_effort=EffortLevel.LOW,
            implementation_time="45 minutes",
            estimated_monthly_cost="$4.60 per EC2 instance + $2 per ECS/EKS task (Runtime Monitoring)",
            prerequisites=[
                "GuardDuty enabled",
                "Runtime Monitoring feature enabled",
                "EC2/ECS/EKS workloads",
            ],
        ),
        # GCP Strategy 1: Cloud Logging IPC Detection
        DetectionStrategy(
            strategy_id="t1559-gcp-ipc-logging",
            name="GCP Cloud Logging IPC Mechanism Detection",
            description=(
                "Monitor GCP Cloud Logging for suspicious IPC mechanism creation including "
                "named pipes, UNIX sockets, and shared memory on GCE instances and GKE containers."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_instance" OR resource.type="k8s_container"
(jsonPayload.syscall="mkfifo" OR
 jsonPayload.syscall="mknod" OR
 jsonPayload.syscall="socketpair" OR
 jsonPayload.syscall="shmget" OR
 jsonPayload.syscall="shmat" OR
 textPayload=~"CreateNamedPipe|CreatePipe|CallNamedPipe")
severity >= WARNING""",
                gcp_terraform_template="""# GCP: IPC mechanism creation detection

variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "alert_email" {
  description = "Email address for security alerts"
  type        = string
}

# Step 1: Create log-based metric for IPC creation
resource "google_logging_metric" "ipc_creation" {
  project = var.project_id
  name    = "ipc-mechanism-creation"
  filter  = <<-EOT
    resource.type="gce_instance" OR resource.type="k8s_container"
    (jsonPayload.syscall="mkfifo" OR
     jsonPayload.syscall="mknod" OR
     jsonPayload.syscall="socketpair" OR
     jsonPayload.syscall="shmget" OR
     jsonPayload.syscall="shmat")
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
  display_name = "IPC Abuse Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 3: Create alert policy
resource "google_monitoring_alert_policy" "ipc_creation" {
  project      = var.project_id
  display_name = "IPC Mechanism Abuse Detection"
  combiner     = "OR"

  conditions {
    display_name = "Suspicious IPC creation detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.ipc_creation.name}\" AND resource.type=\"gce_instance\""
      duration        = "60s"
      comparison      = "COMPARISON_GT"
      threshold_value = 5
      aggregations {
        alignment_period     = "300s"
        per_series_aligner   = "ALIGN_RATE"
        cross_series_reducer = "REDUCE_SUM"
        group_by_fields      = ["resource.instance_id"]
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "1800s"
  }

  documentation {
    content   = <<-EOT
      # Inter-Process Communication Abuse Detected (T1559)

      Suspicious IPC mechanism creation detected including named pipes, sockets, or shared memory.

      ## Investigation Steps:
      1. Identify the process creating IPC objects
      2. Review process command line and parent relationships
      3. Check for malicious binaries or scripts
      4. Examine network connections from the process
      5. Search for persistence mechanisms

      ## Containment:
      - Terminate suspicious processes
      - Remove malicious IPC objects
      - Enable kernel security modules
      - Deploy endpoint protection
    EOT
    mime_type = "text/markdown"
  }
}

output "log_metric_name" {
  description = "Log-based metric name"
  value       = google_logging_metric.ipc_creation.name
}

output "alert_policy_id" {
  description = "Alert policy ID"
  value       = google_monitoring_alert_policy.ipc_creation.id
}""",
                alert_severity="high",
                alert_title="GCP: Suspicious IPC Creation Detected",
                alert_description_template=(
                    "Suspicious IPC mechanism creation detected on GCE instance {instance_id}. "
                    "Syscall: {syscall}. Review audit logs for process details."
                ),
                investigation_steps=[
                    "Identify the GCE instance or GKE pod affected",
                    "Review Cloud Audit Logs for specific syscalls",
                    "Examine process tree and relationships",
                    "Check for recently created files or scripts",
                    "Review VPC Flow Logs for network activity",
                    "Identify initial access vector",
                    "Search for similar patterns across other instances",
                    "Analyse command execution history",
                ],
                containment_actions=[
                    "Terminate suspicious processes",
                    "Remove malicious IPC objects and files",
                    "Create forensic snapshot before remediation",
                    "Rotate service account keys",
                    "Enable OS Config for security patching",
                    "Configure shielded VMs for future instances",
                    "Deploy Security Command Center for threat detection",
                    "Review and tighten firewall rules",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude authorised system services and database processes. Adjust threshold based on environment baseline.",
            detection_coverage="65% - captures UNIX IPC mechanisms. Requires audit logging for comprehensive coverage.",
            evasion_considerations="Attackers may disable audit logging or use standard file descriptors. Requires proper kernel audit configuration.",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1.5 hours",
            estimated_monthly_cost="$5-20 (depends on log volume)",
            prerequisites=[
                "GCE/GKE audit logging enabled",
                "Cloud Logging configured",
                "OS audit daemon (auditd) installed",
            ],
        ),
        # GCP Strategy 2: Security Command Center
        DetectionStrategy(
            strategy_id="t1559-gcp-scc-ipc",
            name="GCP Security Command Center IPC Detection",
            description=(
                "Leverage Security Command Center to detect suspicious inter-process communication "
                "patterns and anomalous process behaviour in GCP workloads."
            ),
            detection_type=DetectionType.SECURITY_COMMAND_CENTER,
            aws_service="n/a",
            gcp_service="security_command_center",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                scc_finding_categories=[
                    "Execution: Suspicious Process",
                    "Execution: Added Binary Executed",
                    "Persistence: Launch Suspicious Process",
                ],
                gcp_terraform_template="""# GCP: Security Command Center IPC detection

variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "alert_email" {
  description = "Email address for security alerts"
  type        = string
}

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "email" {
  project      = var.project_id
  display_name = "IPC Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create Pub/Sub topic for SCC findings
resource "google_pubsub_topic" "scc_findings" {
  project = var.project_id
  name    = "scc-ipc-abuse-findings"
}

resource "google_pubsub_subscription" "scc_findings" {
  project = var.project_id
  name    = "scc-ipc-abuse-sub"
  topic   = google_pubsub_topic.scc_findings.name
}

# Step 3: Configure SCC notification
resource "google_scc_notification_config" "ipc_abuse" {
  config_id    = "ipc-abuse-notifications"
  organization = var.project_id
  pubsub_topic = google_pubsub_topic.scc_findings.id

  streaming_config {
    filter = <<-EOT
      category="Execution: Suspicious Process"
      OR category="Execution: Added Binary Executed"
      OR category="Persistence: Launch Suspicious Process"
    EOT
  }
}

output "pubsub_topic" {
  description = "Pub/Sub topic for SCC findings"
  value       = google_pubsub_topic.scc_findings.name
}

output "notification_config_id" {
  description = "SCC notification config ID"
  value       = google_scc_notification_config.ipc_abuse.config_id
}""",
                alert_severity="high",
                alert_title="GCP: Security Command Center IPC Abuse Detection",
                alert_description_template=(
                    "Security Command Center detected suspicious process activity indicating IPC abuse. "
                    "Review finding details for investigation guidance."
                ),
                investigation_steps=[
                    "Review SCC finding details and evidence",
                    "Identify affected workload and cluster",
                    "Analyse process tree and execution flow",
                    "Check for anomalous IPC patterns",
                    "Review container image and vulnerabilities",
                    "Examine lateral movement indicators",
                    "Check for credential access attempts",
                    "Review related security findings",
                ],
                containment_actions=[
                    "Terminate affected workloads immediately",
                    "Isolate compromised instances or nodes",
                    "Rotate service account keys and credentials",
                    "Implement runtime security policies",
                    "Enable GKE Sandbox (gVisor) for containers",
                    "Deploy Binary Authorisation",
                    "Review and update security policies",
                    "Enable Event Threat Detection",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Minimal tuning required. SCC uses threat intelligence and ML baselines.",
            detection_coverage="85% - comprehensive threat detection using multiple signals",
            evasion_considerations="Difficult to evade SCC threat intelligence. Advanced threats may still use novel techniques.",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$20-40 (Security Command Center Premium)",
            prerequisites=[
                "Security Command Center Premium enabled",
                "Event Threat Detection enabled",
                "GCE/GKE security features enabled",
            ],
        ),
    ],
    recommended_order=[
        "t1559-guardduty-ipc",
        "t1559-gcp-scc-ipc",
        "t1559-aws-ipc-monitoring",
        "t1559-gcp-ipc-logging",
    ],
    total_effort_hours=5.5,
    coverage_improvement="+15% improvement for Execution tactic",
)
