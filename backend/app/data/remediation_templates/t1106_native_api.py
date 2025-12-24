"""
T1106 - Native API

Adversaries interact with native OS application programming interfaces to execute
behaviours by calling low-level kernel services involving hardware, memory, and processes.
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
    technique_id="T1106",
    technique_name="Native API",
    tactic_ids=["TA0002"],
    mitre_url="https://attack.mitre.org/techniques/T1106/",
    threat_context=ThreatContext(
        description=(
            "Adversaries abuse native operating system APIs to execute malicious behaviours whilst "
            "evading detection. By calling low-level kernel services directly through syscalls or "
            "user-mode libraries, attackers can bypass higher-level security hooks and API monitoring. "
            "Techniques include direct syscall invocation, dynamic API resolution using LoadLibrary() "
            "and GetProcAddress(), and framework abstraction layers. In cloud environments, this occurs "
            "on compromised EC2 instances, GCE VMs, or container workloads where attackers leverage native "
            "APIs for process creation, memory manipulation, and network operations."
        ),
        attacker_goal="Execute malicious operations using native OS APIs to evade user-mode hooks and security monitoring",
        why_technique=[
            "Bypasses user-mode API hooks and security monitoring",
            "Enables direct syscall invocation to evade detection",
            "Obfuscates malicious functionality through dynamic API resolution",
            "Provides low-level access to system resources",
            "Facilitates process injection and memory manipulation",
            "Difficult to detect without kernel-level monitoring",
            "Commonly used by advanced malware and APT groups",
            "Enables execution without cmd.exe or PowerShell",
        ],
        known_threat_actors=[],
        recent_campaigns=[
            Campaign(
                name="Operation Dream Job",
                year=2020,
                description="Lazarus Group used native APIs including HttpOpenRequestA and InternetReadFile for C2 communications and VirtualAlloc/WriteProcessMemory for process injection",
                reference_url="https://attack.mitre.org/campaigns/C0022/",
            ),
            Campaign(
                name="Conti Ransomware Operations",
                year=2021,
                description="Conti ransomware leveraged native Windows APIs for service discovery, process creation, and defence evasion during enterprise-wide encryption campaigns",
                reference_url="https://attack.mitre.org/software/S0575/",
            ),
            Campaign(
                name="Emotet Botnet Resurgence",
                year=2020,
                description="Emotet malware used CreateProcess() API for process creation and native networking APIs for command and control without PowerShell or cmd.exe",
                reference_url="https://attack.mitre.org/software/S0367/",
            ),
            Campaign(
                name="Black Basta Discovery Operations",
                year=2022,
                description="Black Basta ransomware employed native APIs for system and network discovery whilst evading traditional command-line monitoring",
                reference_url="https://attack.mitre.org/software/S1070/",
            ),
        ],
        prevalence="very_common",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "Native API abuse is a fundamental technique used by sophisticated malware and APT groups "
            "to evade detection. It enables attackers to bypass user-mode security hooks, execute code "
            "without traditional indicators (cmd.exe, PowerShell), and perform low-level operations "
            "difficult to monitor. The technique is prevalent in ransomware, banking trojans, and APT "
            "toolkits, making it a high-severity threat requiring kernel-level monitoring and behavioural "
            "analytics for effective detection."
        ),
        business_impact=[
            "Evasion of traditional endpoint detection solutions",
            "Execution of ransomware without command-line indicators",
            "Process injection and credential theft from memory",
            "Lateral movement using native networking APIs",
            "Defence evasion through direct syscall invocation",
            "Data exfiltration via low-level network APIs",
            "Persistence mechanisms difficult to detect and remove",
        ],
        typical_attack_phase="execution",
        often_precedes=["T1055", "T1003", "T1071", "T1059"],
        often_follows=["T1566", "T1190", "T1133", "T1078.004"],
    ),
    detection_strategies=[
        # AWS Strategy 1: GuardDuty Runtime Monitoring
        DetectionStrategy(
            strategy_id="t1106-guardduty-runtime",
            name="AWS GuardDuty Runtime Monitoring for Native API Abuse",
            description=(
                "GuardDuty Runtime Monitoring detects suspicious API call patterns, unusual library "
                "loads (ntdll.dll, kernel32.dll), and direct syscall invocations on EC2 instances "
                "and ECS/EKS containers that indicate native API abuse."
            ),
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "Execution:Runtime/NewBinaryExecuted",
                    "Execution:Runtime/NewLibraryLoaded",
                    "DefenseEvasion:Runtime/FilelessExecution",
                    "DefenseEvasion:Runtime/ProcessInjection.Proc",
                    "DefenseEvasion:Runtime/ProcessInjection.Ptrace",
                    "Execution:Runtime/ReverseShell",
                ],
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: GuardDuty Runtime Monitoring for native API abuse detection

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

  # Step 2: Create SNS topic for native API alerts
  NativeAPIAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: Native API Abuse Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 3: Route native API findings to alerts
  NativeAPIRule:
    Type: AWS::Events::Rule
    Properties:
      Name: T1106-NativeAPIDetection
      Description: Alert on GuardDuty native API abuse findings
      EventPattern:
        source: [aws.guardduty]
        detail:
          type:
            - prefix: "Execution:Runtime/"
            - prefix: "DefenseEvasion:Runtime/"
      State: ENABLED
      Targets:
        - Id: SNSTarget
          Arn: !Ref NativeAPIAlertTopic

  SNSTopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref NativeAPIAlertTopic]
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref NativeAPIAlertTopic

Outputs:
  GuardDutyDetectorId:
    Description: GuardDuty detector ID
    Value: !Ref GuardDutyDetector
  AlertTopicArn:
    Description: SNS topic for alerts
    Value: !Ref NativeAPIAlertTopic""",
                terraform_template="""# GuardDuty Runtime Monitoring for native API abuse detection

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

# Step 2: Create SNS topic for native API alerts
resource "aws_sns_topic" "native_api_alerts" {
  name         = "guardduty-native-api-alerts"
  display_name = "Native API Abuse Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.native_api_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 3: Route native API findings to alerts
resource "aws_cloudwatch_event_rule" "native_api" {
  name        = "guardduty-native-api-detection"
  description = "Alert on GuardDuty native API abuse findings"

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
  rule      = aws_cloudwatch_event_rule.native_api.name
  target_id = "SNSTarget"
  arn       = aws_sns_topic.native_api_alerts.arn
}

resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.native_api_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.native_api_alerts.arn
    }]
  })
}

output "guardduty_detector_id" {
  description = "GuardDuty detector ID"
  value       = aws_guardduty_detector.main.id
}

output "alert_topic_arn" {
  description = "SNS topic for alerts"
  value       = aws_sns_topic.native_api_alerts.arn
}""",
                alert_severity="high",
                alert_title="GuardDuty: Native API Abuse Detected",
                alert_description_template=(
                    "GuardDuty detected native API abuse activity: {finding_type}. "
                    "Resource: {resource}. Principal: {principal}. "
                    "This indicates potential malware or advanced evasion techniques requiring investigation."
                ),
                investigation_steps=[
                    "Identify the affected EC2 instance, container, or EKS pod",
                    "Review the specific API calls and library loads detected",
                    "Examine the process tree and parent-child relationships",
                    "Check for suspicious DLL loads (ntdll.dll, kernel32.dll) from unusual locations",
                    "Analyse network connections from the affected process",
                    "Review CloudTrail for suspicious API calls preceding the detection",
                    "Search for indicators of compromise (hashes, domains, IPs)",
                    "Check for similar behaviour patterns across other instances",
                ],
                containment_actions=[
                    "Immediately isolate the affected instance/container",
                    "Terminate suspicious processes using native APIs",
                    "Capture memory dump and forensic artefacts",
                    "Rotate all credentials accessible from the instance",
                    "Review and revoke IAM roles/instance profiles",
                    "Deploy endpoint detection and response (EDR) agents",
                    "Apply security patches and harden configurations",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist legitimate software with unusual library loading patterns (security tools, debuggers, performance monitoring). Exclude authorised DevOps and deployment processes.",
            detection_coverage="70% - covers common native API abuse patterns on supported platforms (EC2, ECS, EKS)",
            evasion_considerations="Advanced attackers may use novel syscall techniques or obfuscation methods not yet detected by runtime analysis. Direct kernel-level syscalls may evade user-mode monitoring.",
            implementation_effort=EffortLevel.LOW,
            implementation_time="45 minutes",
            estimated_monthly_cost="£3.40 per EC2 instance + £1.50 per ECS/EKS task (Runtime Monitoring pricing)",
            prerequisites=[
                "AWS account with GuardDuty access",
                "EC2/ECS/EKS workloads",
                "SSM agent for EC2 automated deployment",
            ],
        ),
        # AWS Strategy 2: CloudWatch Logs Analysis for Syscall Patterns
        DetectionStrategy(
            strategy_id="t1106-cloudwatch-syscall-monitoring",
            name="CloudWatch Logs Syscall Pattern Detection",
            description=(
                "Monitor system audit logs for suspicious syscall patterns indicative of native API "
                "abuse, including direct kernel invocations, unusual library loads, and API sequences "
                "associated with malware behaviour on both Windows and Linux systems."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, @message, host, process_name, syscall, dll_name
| filter @message like /NtCreateProcess|NtCreateThread|NtAllocateVirtualMemory/
   or @message like /LoadLibrary|GetProcAddress|VirtualAlloc/
   or @message like /syscall|int 0x80|sysenter/
   or @message like /kernel32[.]dll|ntdll[.]dll/ and @message like /unusual|suspicious/
| parse @message /(?<calling_process>[^ ]+).*(?<api_function>[a-zA-Z0-9_]+)[(](?<arguments>[^)]+)[)]/
| stats count() by process_name, api_function, calling_process
| sort count desc
| limit 100""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: CloudWatch-based native API syscall pattern detection

Parameters:
  SystemLogGroup:
    Type: String
    Description: CloudWatch log group for system/audit logs (e.g., /var/log/audit/audit.log)
  AlertEmail:
    Type: String
    Description: Email address for security alerts

Resources:
  # Step 1: Create metric filter for native API indicators
  NativeAPIMetricFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref SystemLogGroup
      FilterPattern: '[timestamp, msg, ...] (msg=~"NtCreate*" || msg=~"LoadLibrary" || msg=~"GetProcAddress" || msg=~"syscall")'
      MetricTransformations:
        - MetricName: NativeAPIAbuse
          MetricNamespace: Security/T1106
          MetricValue: "1"
          DefaultValue: 0

  # Step 2: Create CloudWatch alarm
  NativeAPIAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1106-NativeAPIAbuse
      AlarmDescription: Detected suspicious native API usage patterns
      MetricName: NativeAPIAbuse
      Namespace: Security/T1106
      Statistic: Sum
      Period: 300
      Threshold: 5
      ComparisonOperator: GreaterThanOrEqualToThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching
      AlarmActions:
        - !Ref AlertTopic

  # Step 3: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: Native API Abuse Alerts
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
    Value: !Ref NativeAPIAlarm""",
                terraform_template="""# CloudWatch-based native API syscall pattern detection

variable "system_log_group" {
  description = "CloudWatch log group for system/audit logs"
  type        = string
}

variable "alert_email" {
  description = "Email address for security alerts"
  type        = string
}

# Step 1: Create metric filter for native API indicators
resource "aws_cloudwatch_log_metric_filter" "native_api" {
  name           = "native-api-abuse-indicators"
  log_group_name = var.system_log_group
  pattern        = "[timestamp, msg, ...] (msg=~\"NtCreate*\" || msg=~\"LoadLibrary\" || msg=~\"GetProcAddress\" || msg=~\"syscall\")"

  metric_transformation {
    name          = "NativeAPIAbuse"
    namespace     = "Security/T1106"
    value         = "1"
    default_value = 0
  }
}

# Step 2: Create CloudWatch alarm
resource "aws_cloudwatch_metric_alarm" "native_api" {
  alarm_name          = "native-api-abuse-detected"
  alarm_description   = "Detected suspicious native API usage patterns"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "NativeAPIAbuse"
  namespace           = "Security/T1106"
  period              = 300
  statistic           = "Sum"
  threshold           = 5
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

# Step 3: SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name         = "native-api-abuse-alerts"
  display_name = "Native API Abuse Alerts"
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
  value       = aws_cloudwatch_metric_alarm.native_api.alarm_name
}""",
                alert_severity="high",
                alert_title="Native API Abuse Indicators Detected",
                alert_description_template=(
                    "Suspicious native API usage detected on instance {instance_id}. "
                    "Process: {process_name}. API function: {api_function}. "
                    "Multiple calls detected within monitoring window."
                ),
                investigation_steps=[
                    "Review audit logs for specific API calls and syscalls",
                    "Identify the calling process and command-line arguments",
                    "Check if the process is legitimate or malicious",
                    "Examine the frequency and sequence of API calls",
                    "Review network connections from the calling process",
                    "Check for recently dropped files or modified binaries",
                    "Search for persistence mechanisms and scheduled tasks",
                    "Correlate with threat intelligence feeds for known malware signatures",
                ],
                containment_actions=[
                    "Terminate the malicious process using native APIs",
                    "Enable enhanced logging (Sysmon on Windows, auditd on Linux)",
                    "Deploy application control policies (AppLocker, WDAC)",
                    "Restrict API access via security policies",
                    "Enable kernel-level protections (PatchGuard, HVCI on Windows)",
                    "Deploy endpoint detection and response (EDR) solutions",
                    "Review and harden security group configurations",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude legitimate system utilities, debuggers, monitoring tools, and authorised security software. Requires Sysmon (Windows) or auditd (Linux) configured with detailed logging.",
            detection_coverage="65% - depends on audit log configuration and coverage. Requires enhanced system logging.",
            evasion_considerations="Attackers may disable logging services, use obfuscation, or employ direct kernel-level syscalls to evade detection. Limited effectiveness without kernel-level monitoring (Sysmon, auditd).",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="£7.50-£22.50 (depends on log volume)",
            prerequisites=[
                "Enhanced system logging enabled (Sysmon/auditd)",
                "CloudWatch agent configured",
                "System logs forwarded to CloudWatch",
            ],
        ),
        # GCP Strategy: Cloud Logging for Native API Detection
        DetectionStrategy(
            strategy_id="t1106-gcp-logging-native-api",
            name="GCP Cloud Logging Native API Abuse Detection",
            description=(
                "Monitor GCP Cloud Logging for suspicious native API usage patterns on GCE instances "
                "and GKE containers, including unusual syscalls, library loads, and API call sequences "
                "indicative of malware or advanced evasion techniques."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_instance" OR resource.type="k8s_container"
(jsonPayload.syscall=~"execve|fork|clone|ptrace|mmap|mprotect" OR
 textPayload=~"LoadLibrary|GetProcAddress|NtCreateProcess|NtCreateThread" OR
 textPayload=~"libc\\.so|libdl\\.so|syscall" OR
 jsonPayload.api_call=~"VirtualAlloc|WriteProcessMemory|CreateRemoteThread")
severity >= WARNING""",
                gcp_terraform_template="""# GCP: Native API abuse detection via Cloud Logging

variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "alert_email" {
  description = "Email address for security alerts"
  type        = string
}

# Step 1: Create log-based metric for native API abuse
resource "google_logging_metric" "native_api" {
  project = var.project_id
  name    = "native-api-abuse-indicators"
  filter  = <<-EOT
    resource.type="gce_instance" OR resource.type="k8s_container"
    (jsonPayload.syscall=~"execve|fork|clone|ptrace|mmap|mprotect" OR
     textPayload=~"LoadLibrary|GetProcAddress|NtCreateProcess|NtCreateThread" OR
     textPayload=~"libc\\.so|libdl\\.so|syscall" OR
     jsonPayload.api_call=~"VirtualAlloc|WriteProcessMemory|CreateRemoteThread")
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
      description = "System call or API function"
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
  display_name = "Native API Abuse Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 3: Create alert policy
resource "google_monitoring_alert_policy" "native_api" {
  project      = var.project_id
  display_name = "Native API Abuse Detection"
  combiner     = "OR"

  conditions {
    display_name = "Native API abuse indicators detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.native_api.name}\" AND resource.type=\"gce_instance\""
      duration        = "60s"
      comparison      = "COMPARISON_GT"
      threshold_value = 5
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "1800s"
  }

  documentation {
    content   = <<-EOT
      # Native API Abuse Detected (T1106)

      Suspicious native API usage patterns detected via syscalls or library functions.

      ## Investigation Steps:
      1. Identify the process using native APIs
      2. Review audit logs for API call sequences
      3. Check for malicious binaries or libraries
      4. Examine network connections from the process
      5. Search for indicators of compromise

      ## Containment:
      - Terminate malicious processes
      - Deploy security monitoring agents
      - Enable application control policies
      - Restrict API access via security policies
    EOT
    mime_type = "text/markdown"
  }
}

output "log_metric_name" {
  description = "Log-based metric name"
  value       = google_logging_metric.native_api.name
}

output "alert_policy_id" {
  description = "Alert policy ID"
  value       = google_monitoring_alert_policy.native_api.id
}""",
                alert_severity="high",
                alert_title="GCP: Native API Abuse Detected",
                alert_description_template=(
                    "Native API abuse indicators detected on GCE instance {instance_id}. "
                    "Syscall/API: {syscall}. Review audit logs for detailed analysis."
                ),
                investigation_steps=[
                    "Identify the GCE instance or GKE pod affected",
                    "Review Cloud Audit Logs for specific syscalls and API calls",
                    "Examine the process tree and execution context",
                    "Check for recently loaded shared libraries (.so, .dll files)",
                    "Review VPC Flow Logs for suspicious network activity",
                    "Identify initial access vector (SSH keys, service accounts, vulnerabilities)",
                    "Search for similar patterns across other instances",
                    "Correlate with Security Command Center findings",
                ],
                containment_actions=[
                    "Terminate the compromised instance or pod",
                    "Create forensic snapshot before termination",
                    "Rotate service account keys and credentials",
                    "Enable OS Login and disable direct SSH access",
                    "Deploy Security Command Centre Premium for advanced threat detection",
                    "Configure shielded VMs with secure boot and vTPM",
                    "Review and tighten firewall rules and VPC configurations",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude authorised system utilities, monitoring agents (Cloud Ops Agent, Stackdriver), debuggers, and DevOps tools. Requires OS-level audit logging configured.",
            detection_coverage="65% - depends on OS-level audit logging configuration. Primarily covers Linux and Windows syscall patterns.",
            evasion_considerations="Attackers may disable audit logging, use novel syscall techniques, or employ kernel-level rootkits to evade detection. Requires proper OS-level audit configuration.",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1.5 hours",
            estimated_monthly_cost="£3.75-£15 (depends on log ingestion volume)",
            prerequisites=[
                "GCE/GKE audit logging enabled",
                "Cloud Logging configured",
                "OS-level audit daemon (auditd/Sysmon) installed",
            ],
        ),
        # AWS Strategy 3: EventBridge Pattern Detection
        DetectionStrategy(
            strategy_id="t1106-eventbridge-api-patterns",
            name="EventBridge Native API Call Pattern Detection",
            description=(
                "Monitor CloudTrail API calls for patterns indicative of native API abuse, including "
                "unusual sequences of RunInstances, CreateFunction, or UpdateFunctionCode that may "
                "indicate automated malware deployment using native cloud APIs."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: EventBridge pattern detection for suspicious native API usage

Parameters:
  AlertEmail:
    Type: String
    Description: Email address for security alerts

Resources:
  # Step 1: EventBridge rule for suspicious API patterns
  SuspiciousAPIPatternRule:
    Type: AWS::Events::Rule
    Properties:
      Name: T1106-SuspiciousNativeAPIPattern
      Description: Detect suspicious native cloud API usage patterns
      EventPattern:
        source: [aws.ec2, aws.lambda, aws.ecs]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName:
            - RunInstances
            - CreateFunction
            - UpdateFunctionCode
            - RegisterTaskDefinition
            - RunTask
          userAgent:
            - prefix: python
            - prefix: boto3
            - prefix: aws-cli
      State: ENABLED
      Targets:
        - Id: SNSTarget
          Arn: !Ref AlertTopic

  # Step 2: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: Native API Pattern Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 3: SNS topic policy
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
  RuleArn:
    Description: EventBridge rule ARN
    Value: !GetAtt SuspiciousAPIPatternRule.Arn""",
                terraform_template="""# EventBridge pattern detection for suspicious native API usage

variable "alert_email" {
  description = "Email address for security alerts"
  type        = string
}

# Step 1: EventBridge rule for suspicious API patterns
resource "aws_cloudwatch_event_rule" "suspicious_api_pattern" {
  name        = "suspicious-native-api-pattern"
  description = "Detect suspicious native cloud API usage patterns"

  event_pattern = jsonencode({
    source      = ["aws.ec2", "aws.lambda", "aws.ecs"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "RunInstances",
        "CreateFunction",
        "UpdateFunctionCode",
        "RegisterTaskDefinition",
        "RunTask"
      ]
      userAgent = [
        { prefix = "python" },
        { prefix = "boto3" },
        { prefix = "aws-cli" }
      ]
    }
  })
}

# Step 2: SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name         = "native-api-pattern-alerts"
  display_name = "Native API Pattern Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 3: EventBridge target
resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.suspicious_api_pattern.name
  target_id = "SNSTarget"
  arn       = aws_sns_topic.alerts.arn
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

output "rule_arn" {
  description = "EventBridge rule ARN"
  value       = aws_cloudwatch_event_rule.suspicious_api_pattern.arn
}""",
                alert_severity="medium",
                alert_title="Suspicious Native Cloud API Pattern Detected",
                alert_description_template=(
                    "Suspicious cloud API usage detected: {eventName}. "
                    "Principal: {principal}. User agent: {userAgent}. "
                    "Review CloudTrail for automated malware deployment patterns."
                ),
                investigation_steps=[
                    "Review CloudTrail logs for the API call sequence",
                    "Identify the IAM principal (user, role, service account)",
                    "Check the user agent and source IP address",
                    "Examine the created resources (instances, functions, tasks)",
                    "Review IAM permissions and access patterns",
                    "Search for indicators of credential compromise",
                    "Check for similar API calls from the same principal",
                ],
                containment_actions=[
                    "Suspend or revoke the IAM credentials used",
                    "Terminate suspicious instances, functions, or tasks",
                    "Enable MFA for privileged accounts",
                    "Review and tighten IAM policies",
                    "Enable AWS Organizations SCPs for additional controls",
                    "Deploy AWS Config rules to monitor resource creation",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist authorised automation tools, CI/CD pipelines, and infrastructure-as-code deployments. Focus on unusual user agents and IP addresses.",
            detection_coverage="50% - covers cloud API usage patterns but not OS-level native API abuse",
            evasion_considerations="Attackers may use legitimate automation tools or obfuscate user agents. Limited to cloud API calls, not OS-level syscalls.",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="£0.75-£2.25 (EventBridge pricing)",
            prerequisites=[
                "CloudTrail enabled with management events",
                "EventBridge access",
            ],
        ),
    ],
    recommended_order=[
        "t1106-guardduty-runtime",
        "t1106-cloudwatch-syscall-monitoring",
        "t1106-eventbridge-api-patterns",
        "t1106-gcp-logging-native-api",
    ],
    total_effort_hours=4.75,
    coverage_improvement="+30% improvement for Execution tactic detection",
)
