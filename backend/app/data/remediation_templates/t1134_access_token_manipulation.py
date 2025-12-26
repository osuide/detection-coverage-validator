"""
T1134 - Access Token Manipulation

Adversaries may modify access tokens to operate under different user or system
security contexts to bypass access controls and/or elevate privileges.
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
    technique_id="T1134",
    technique_name="Access Token Manipulation",
    tactic_ids=["TA0004", "TA0005"],
    mitre_url="https://attack.mitre.org/techniques/T1134/",
    threat_context=ThreatContext(
        description=(
            "Adversaries may modify Windows access tokens to operate under different user "
            "or system security contexts, enabling them to bypass access controls and elevate "
            "privileges. In cloud environments, this primarily affects Windows EC2 instances and "
            "GCE VMs where attackers leverage built-in Windows API functions to steal tokens from "
            "running processes and apply them to existing or new processes, enabling lateral "
            "movement across cloud infrastructure and unauthorised access to sensitive resources."
        ),
        attacker_goal="Bypass access controls and escalate privileges to SYSTEM level on cloud Windows instances",
        why_technique=[
            "Token theft enables privilege escalation from administrator to SYSTEM",
            "Impersonation tokens allow access to network resources under different identities",
            "Parent PID spoofing helps evade endpoint detection and response (EDR) solutions",
            "Stolen tokens can access instance metadata and cloud credentials",
            "Token manipulation enables lateral movement to other cloud instances",
            "Creates process trees that appear legitimate to security tools",
            "SID-History injection can grant access to cross-forest resources in hybrid environments",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="stable",
        severity_score=8,
        severity_reasoning=(
            "Access Token Manipulation is a critical privilege escalation and defence evasion "
            "technique. On cloud Windows instances, successful token manipulation provides "
            "attackers with SYSTEM-level access, enabling full control over the instance, "
            "access to instance credentials, and potential lateral movement to other cloud "
            "resources. The technique is particularly dangerous in hybrid cloud environments "
            "where domain-joined instances can become pivots to on-premises infrastructure."
        ),
        business_impact=[
            "Complete compromise of Windows cloud instances",
            "Unauthorised access to instance IAM role credentials",
            "Lateral movement to other instances and cloud resources",
            "Ransomware deployment across Windows workloads",
            "Data exfiltration from databases and file shares",
            "Persistence through SYSTEM-level access mechanisms",
            "Evasion of endpoint security and monitoring tools",
        ],
        typical_attack_phase="privilege_escalation",
        often_precedes=["T1003", "T1021", "T1558", "T1078"],
        often_follows=["T1078.004", "T1190", "T1133", "T1210"],
    ),
    detection_strategies=[
        # Strategy 1: AWS GuardDuty Runtime Monitoring
        DetectionStrategy(
            strategy_id="t1134-guardduty-runtime",
            name="AWS GuardDuty Runtime Monitoring for Token Manipulation",
            description=(
                "AWS GuardDuty Runtime Monitoring detects suspicious process behaviour on "
                "Windows EC2 instances, including token manipulation attempts through API calls "
                "such as OpenProcessToken, DuplicateTokenEx, and ImpersonateLoggedOnUser."
            ),
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "PrivilegeEscalation:Runtime/NewUserCreated",
                    "PrivilegeEscalation:Runtime/ContainerMountsHostDirectory",
                    "Execution:Runtime/NewBinaryExecuted",
                    "Defense Evasion:Runtime/ProcessInjectionAttempt",
                    "PrivilegeEscalation:Runtime/AnomalousBehavior",
                ],
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: GuardDuty Runtime Monitoring for token manipulation detection

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
  SecurityAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: Token Manipulation Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 3: Route privilege escalation findings to email
  TokenManipulationRule:
    Type: AWS::Events::Rule
    Properties:
      Name: T1134-TokenManipulation
      Description: Alert on access token manipulation attempts
      EventPattern:
        source: [aws.guardduty]
        detail-type:
          - GuardDuty Finding
        detail:
          type:
            - prefix: "PrivilegeEscalation:Runtime"
            - prefix: "DefenseEvasion:Runtime"
            - prefix: "Execution:Runtime"
      State: ENABLED
      Targets:
        - Id: AlertTopic
          Arn: !Ref SecurityAlertTopic

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref SecurityAlertTopic]
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref SecurityAlertTopic""",
                terraform_template="""# GuardDuty Runtime Monitoring for token manipulation

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
resource "aws_sns_topic" "token_manipulation_alerts" {
  name         = "token-manipulation-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "Token Manipulation Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.token_manipulation_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 3: Route privilege escalation findings to email
resource "aws_cloudwatch_event_rule" "token_manipulation" {
  name        = "guardduty-token-manipulation"
  description = "Alert on access token manipulation attempts"
  event_pattern = jsonencode({
    source = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    detail = {
      type = [
        { prefix = "PrivilegeEscalation:Runtime" },
        { prefix = "DefenseEvasion:Runtime" },
        { prefix = "Execution:Runtime" }
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.token_manipulation.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.token_manipulation_alerts.arn
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.token_manipulation_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.token_manipulation_alerts.arn
    Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}""",
                alert_severity="critical",
                alert_title="GuardDuty: Access Token Manipulation Detected",
                alert_description_template=(
                    "Suspicious token manipulation activity detected on instance {instance_id}. "
                    "Finding: {finding_type}. Process: {process_name}. "
                    "This may indicate privilege escalation or defence evasion."
                ),
                investigation_steps=[
                    "Review the GuardDuty finding details and affected Windows instance",
                    "Check Event Viewer Security logs (Event ID 4673, 4674) for privilege use",
                    "Examine running processes and their parent-child relationships",
                    "Review Windows Security Event ID 4688 for process creation with token manipulation",
                    "Check for known token manipulation tools (mimikatz, incognito, JuicyPotato, etc.)",
                    "Investigate recent user logins and session activity",
                    "Review CloudTrail for API calls from the instance IAM role",
                ],
                containment_actions=[
                    "Isolate the instance by modifying security group to block all traffic",
                    "Create a forensic snapshot of the instance for investigation",
                    "Terminate suspicious processes using SSM Session Manager",
                    "Rotate instance IAM role credentials immediately",
                    "Remove the instance from Active Directory if domain-joined",
                    "Terminate the instance if compromise is confirmed",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Exclude known security tools that legitimately use token manipulation; baseline normal administrative activities",
            detection_coverage="65% - detects runtime token manipulation patterns on EC2 instances",
            evasion_considerations="Attackers may use custom tools or API hooking to evade runtime detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="45 minutes",
            estimated_monthly_cost="$4.60 per instance per month for Runtime Monitoring",
            prerequisites=[
                "GuardDuty enabled",
                "SSM Agent on EC2 instances for Runtime Monitoring",
            ],
        ),
        # Strategy 2: Windows Event Log Monitoring
        DetectionStrategy(
            strategy_id="t1134-windows-events",
            name="Windows Event Log Monitoring for Token Manipulation",
            description=(
                "Monitor Windows Security Event Logs sent to CloudWatch for specific event IDs "
                "that indicate token manipulation, including privilege use (4673, 4674), "
                "sensitive privilege use (4672), and process creation with token manipulation."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, EventID, Computer, ProcessName, PrivilegeName, TokenElevationType
| filter EventID in [4672, 4673, 4674, 4688, 4697]
| filter PrivilegeName in ["SeDebugPrivilege", "SeImpersonatePrivilege", "SeAssignPrimaryTokenPrivilege", "SeTcbPrivilege"]
| stats count() as events by Computer, ProcessName, PrivilegeName, bin(10m)
| filter events > 3
| sort @timestamp desc""",
                cloudformation_template='''AWSTemplateFormatVersion: '2010-09-09'
Description: Windows Event Log monitoring for token manipulation

Parameters:
  CloudWatchLogGroup:
    Type: String
    Description: Log group containing Windows Security Event logs
    Default: /aws/ec2/windows/security
  SNSTopicArn:
    Type: String
    Description: SNS topic for alerts

Resources:
  # Step 1: Create metric filter for SeDebugPrivilege usage
  SeDebugPrivilegeFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudWatchLogGroup
      FilterPattern: '[EventID="4673", Privilege="SeDebugPrivilege" || Privilege="SeImpersonatePrivilege" || Privilege="SeAssignPrimaryTokenPrivilege"]'
      MetricTransformations:
        - MetricName: TokenPrivilegeUse
          MetricNamespace: Security/T1134
          MetricValue: "1"

  # Step 2: Create alarm for suspicious privilege use
  TokenManipulationAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1134-TokenManipulation
      AlarmDescription: Suspicious token privilege usage detected
      MetricName: TokenPrivilegeUse
      Namespace: Security/T1134
      Statistic: Sum
      Period: 600
      EvaluationPeriods: 1
      Threshold: 3
      ComparisonOperator: GreaterThanThreshold
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref SNSTopicArn

  # Step 3: Monitor special privileges assigned at logon
  SpecialPrivilegesFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudWatchLogGroup
      FilterPattern: '[EventID="4672", User!="SYSTEM"]'
      MetricTransformations:
        - MetricName: SpecialPrivilegesAssigned
          MetricNamespace: Security/T1134
          MetricValue: "1"''',
                terraform_template="""# Windows Event Log monitoring for token manipulation

variable "cloudwatch_log_group" {
  type        = string
  description = "Log group containing Windows Security Event logs"
  default     = "/aws/ec2/windows/security"
}

variable "alert_email" {
  type        = string
  description = "Email for alerts"
}

resource "aws_sns_topic" "alerts" {
  name = "token-manipulation-windows-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 1: Create metric filter for sensitive privilege usage
resource "aws_cloudwatch_log_metric_filter" "token_privilege_use" {
  name           = "token-privilege-use"
  log_group_name = var.cloudwatch_log_group
  pattern        = "[EventID=\"4673\", Privilege=\"SeDebugPrivilege\" || Privilege=\"SeImpersonatePrivilege\" || Privilege=\"SeAssignPrimaryTokenPrivilege\"]"

  metric_transformation {
    name      = "TokenPrivilegeUse"
    namespace = "Security/T1134"
    value     = "1"
  }
}

# Step 2: Create alarm for suspicious privilege use
resource "aws_cloudwatch_metric_alarm" "token_manipulation" {
  alarm_name          = "T1134-TokenManipulation"
  alarm_description   = "Suspicious token privilege usage detected"
  metric_name         = "TokenPrivilegeUse"
  namespace           = "Security/T1134"
  statistic           = "Sum"
  period              = 600
  evaluation_periods  = 1
  threshold           = 3
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}

# Step 3: Monitor special privileges assigned at logon
resource "aws_cloudwatch_log_metric_filter" "special_privileges" {
  name           = "special-privileges-assigned"
  log_group_name = var.cloudwatch_log_group
  pattern        = "[EventID=\"4672\", User!=\"SYSTEM\"]"

  metric_transformation {
    name      = "SpecialPrivilegesAssigned"
    namespace = "Security/T1134"
    value     = "1"
  }
}""",
                alert_severity="high",
                alert_title="Windows Token Manipulation Detected",
                alert_description_template=(
                    "Suspicious token privilege usage detected on {computer}. "
                    "Process: {process_name}. Privilege: {privilege_name}. "
                    "Event ID: {event_id}. This may indicate token manipulation."
                ),
                investigation_steps=[
                    "Review the full Windows Security Event log context around the alert",
                    "Identify the process using sensitive privileges (SeDebugPrivilege, SeImpersonatePrivilege)",
                    "Check if the process is a known administrative or security tool",
                    "Review process creation chain to identify parent processes",
                    "Search for known token manipulation tool signatures (mimikatz, incognito, potato exploits)",
                    "Check for concurrent network connections or data transfers",
                    "Review recent user logon events (Event ID 4624, 4625)",
                ],
                containment_actions=[
                    "Kill the suspicious process using Task Manager or PowerShell",
                    "Disable the user account if a specific user is compromised",
                    "Isolate the instance from the network immediately",
                    "Force logoff all active user sessions on the instance",
                    "Reset local administrator passwords",
                    "Remove the instance from domain if it's domain-joined",
                    "Rebuild the instance from a known good AMI",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal administrative tool usage; whitelist authorised security software that uses these privileges",
            detection_coverage="75% - catches token manipulation through Windows privilege use events",
            evasion_considerations="Attackers may disable Windows event logging or clear logs after activity",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$10-25 depending on log volume",
            prerequisites=[
                "CloudWatch Agent installed on Windows instances",
                "Windows Security Event logging enabled and forwarded to CloudWatch",
            ],
        ),
        # Strategy 3: Known Token Manipulation Tool Detection
        DetectionStrategy(
            strategy_id="t1134-tool-detection",
            name="Detect Known Token Manipulation Tools",
            description=(
                "Monitor for execution of known token manipulation tools and exploits such as "
                "mimikatz, incognito, JuicyPotato, PrintSpoofer, and other privilege escalation utilities."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, @message, instanceId, processName, commandLine
| filter @message like /mimikatz|incognito|JuicyPotato|RottenPotato|PrintSpoofer|RoguePotato|SweetPotato|token::elevate|token::impersonate|Invoke-TokenManipulation/
| stats count() as executions by instanceId, processName, bin(5m)
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect token manipulation tool execution

Parameters:
  CloudWatchLogGroup:
    Type: String
    Description: Log group containing instance logs
  SNSTopicArn:
    Type: String
    Description: SNS topic for alerts

Resources:
  # Step 1: Create metric filter for token manipulation tools
  TokenToolFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudWatchLogGroup
      FilterPattern: '[time, instance, process, command="*mimikatz*" || command="*incognito*" || command="*JuicyPotato*" || command="*RottenPotato*" || command="*PrintSpoofer*" || command="*token::elevate*"]'
      MetricTransformations:
        - MetricName: TokenManipulationTools
          MetricNamespace: Security/T1134
          MetricValue: "1"

  # Step 2: Create alarm for tool execution
  TokenToolAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1134-TokenManipulationTool
      AlarmDescription: Token manipulation tool detected
      MetricName: TokenManipulationTools
      Namespace: Security/T1134
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 1
      ComparisonOperator: GreaterThanOrEqualToThreshold
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref SNSTopicArn

  # Step 3: Create subscription filter for immediate alerting
  SubscriptionFilter:
    Type: AWS::Logs::SubscriptionFilter
    Properties:
      LogGroupName: !Ref CloudWatchLogGroup
      FilterPattern: '[time, instance, process, command="*mimikatz*" || command="*JuicyPotato*" || command="*token::elevate*"]'
      DestinationArn: !Ref SNSTopicArn""",
                terraform_template="""# Detect token manipulation tool execution

variable "cloudwatch_log_group" {
  type        = string
  description = "Log group containing instance logs"
}

variable "alert_email" {
  type        = string
  description = "Email for alerts"
}

# Step 1: Create metric filter for token manipulation tools
resource "aws_cloudwatch_log_metric_filter" "token_manipulation_tools" {
  name           = "token-manipulation-tools"
  log_group_name = var.cloudwatch_log_group
  pattern        = "[time, instance, process, command=\"*mimikatz*\" || command=\"*incognito*\" || command=\"*JuicyPotato*\" || command=\"*RottenPotato*\" || command=\"*PrintSpoofer*\" || command=\"*token::elevate*\"]"

  metric_transformation {
    name      = "TokenManipulationTools"
    namespace = "Security/T1134"
    value     = "1"
  }
}

# Step 2: Create SNS topic
resource "aws_sns_topic" "alerts" {
  name = "token-tool-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 3: Create alarm for tool execution
resource "aws_cloudwatch_metric_alarm" "token_manipulation_tool" {
  alarm_name          = "T1134-TokenManipulationTool"
  alarm_description   = "Token manipulation tool detected"
  metric_name         = "TokenManipulationTools"
  namespace           = "Security/T1134"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="critical",
                alert_title="Token Manipulation Tool Detected",
                alert_description_template=(
                    "Known token manipulation tool detected on instance {instance_id}. "
                    "Process: {process_name}. Command: {command_line}. "
                    "Immediate investigation required - likely active breach."
                ),
                investigation_steps=[
                    "Identify the exact tool and command executed",
                    "Determine the user account that ran the tool",
                    "Check process parent to identify how the tool was launched",
                    "Review file system for the tool binary and any dropped files",
                    "Search for credential dumps or other artifacts created by the tool",
                    "Check for lateral movement attempts following execution",
                    "Review network connections made during and after tool execution",
                ],
                containment_actions=[
                    "Immediately isolate the instance from the network",
                    "Kill the token manipulation process if still running",
                    "Terminate all user sessions on the instance",
                    "Rotate all credentials that may have been compromised",
                    "Delete the token manipulation tool binary",
                    "Reset local and domain passwords for affected accounts",
                    "Rebuild the instance from a known good state",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist authorised penetration testing with documented approval workflow",
            detection_coverage="90% - catches known tool signatures and command patterns",
            evasion_considerations="Renamed tools, custom tools, or obfuscated commands may evade signature detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1.5 hours",
            estimated_monthly_cost="$5-15 depending on log volume",
            prerequisites=[
                "CloudWatch Logs Agent installed on Windows instances",
                "Process command-line logging enabled",
            ],
        ),
        # Strategy 4: GCP Instance Token Manipulation Detection
        DetectionStrategy(
            strategy_id="t1134-gcp-detection",
            name="GCP: Detect Token Manipulation on Windows GCE Instances",
            description=(
                "Monitor GCP Cloud Logging for token manipulation activity on Windows "
                "Compute Engine instances through system logs and security events."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_instance"
(jsonPayload.EventID=4672 OR jsonPayload.EventID=4673 OR jsonPayload.EventID=4674)
(jsonPayload.PrivilegeName="SeDebugPrivilege"
OR jsonPayload.PrivilegeName="SeImpersonatePrivilege"
OR jsonPayload.PrivilegeName="SeAssignPrimaryTokenPrivilege"
OR textPayload=~"mimikatz|incognito|JuicyPotato|token::elevate")""",
                gcp_terraform_template="""# GCP: Detect token manipulation on Windows GCE instances

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
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log-based metric for token manipulation
resource "google_logging_metric" "token_manipulation" {
  project = var.project_id
  name    = "token-manipulation-attempts"
  filter  = <<-EOT
    resource.type="gce_instance"
    (jsonPayload.EventID=4672 OR jsonPayload.EventID=4673 OR jsonPayload.EventID=4674)
    (jsonPayload.PrivilegeName="SeDebugPrivilege"
    OR jsonPayload.PrivilegeName="SeImpersonatePrivilege"
    OR jsonPayload.PrivilegeName="SeAssignPrimaryTokenPrivilege"
    OR textPayload=~"mimikatz|incognito|JuicyPotato|token::elevate")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "instance_id"
      value_type  = "STRING"
      description = "Instance where token manipulation was detected"
    }
  }

  label_extractors = {
    instance_id = "EXTRACT(resource.labels.instance_id)"
  }
}

# Step 3: Create alert policy
resource "google_monitoring_alert_policy" "token_manipulation" {
  project      = var.project_id
  display_name = "T1134: Access Token Manipulation Detected"
  combiner     = "OR"
  conditions {
    display_name = "Token manipulation activity"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.token_manipulation.name}\" resource.type=\"gce_instance\""
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
    content   = "Access token manipulation detected on Windows GCE instance. Investigate for privilege escalation or defence evasion."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="critical",
                alert_title="GCP: Access Token Manipulation Detected",
                alert_description_template=(
                    "Token manipulation activity detected on Windows GCE instance {instance_id}. "
                    "Event ID: {event_id}. Privilege: {privilege_name}. Investigate immediately."
                ),
                investigation_steps=[
                    "Review the Cloud Logging entry for full event details",
                    "Check the instance's service account permissions",
                    "Review Windows Event Viewer for related security events",
                    "Examine running processes and their privilege levels",
                    "Check for recent API calls made by the instance's service account",
                    "Review VPC Flow Logs for suspicious network activity",
                    "Investigate user accounts and recent authentication events",
                ],
                containment_actions=[
                    "Stop the GCE instance to prevent further compromise",
                    "Create a snapshot for forensic analysis before any changes",
                    "Revoke the instance's service account credentials",
                    "Update firewall rules to isolate the instance",
                    "Remove the instance from Active Directory if domain-joined",
                    "Reset passwords for all accounts that logged into the instance",
                    "Review and remove any unauthorised persistence mechanisms",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal administrative tool usage; exclude authorised security software",
            detection_coverage="70% - detects token manipulation through Windows events and tool signatures",
            evasion_considerations="Custom tools or disabled logging may bypass detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1.5 hours",
            estimated_monthly_cost="$15-30",
            prerequisites=[
                "Cloud Logging API enabled",
                "Ops Agent or Cloud Logging agent installed on Windows GCE instances",
                "Windows Event logging configured",
            ],
        ),
        # Strategy 5: Process Creation with Token Anomalies
        DetectionStrategy(
            strategy_id="t1134-process-anomalies",
            name="Detect Process Creation with Token Anomalies",
            description=(
                "Monitor Windows Event ID 4688 (Process Creation) for processes created with "
                "token elevation, parent PID spoofing, or processes running under different "
                "security contexts than expected."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, EventID, Computer, NewProcessName, ParentProcessName,
       TokenElevationType, SubjectUserName, TargetUserName
| filter EventID = 4688
| filter TokenElevationType != "%%1936" or SubjectUserName != TargetUserName
| stats count() as suspicious_processes by Computer, NewProcessName, ParentProcessName, bin(15m)
| filter suspicious_processes > 2
| sort @timestamp desc""",
                cloudformation_template='''AWSTemplateFormatVersion: '2010-09-09'
Description: Detect process creation with token anomalies

Parameters:
  CloudWatchLogGroup:
    Type: String
    Description: Log group containing Windows Event logs
    Default: /aws/ec2/windows/security
  SNSTopicArn:
    Type: String
    Description: SNS topic for alerts

Resources:
  # Step 1: Monitor processes created with elevated tokens
  ElevatedTokenProcessFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudWatchLogGroup
      FilterPattern: '[EventID="4688", TokenType="%%1937"]'
      MetricTransformations:
        - MetricName: ElevatedTokenProcess
          MetricNamespace: Security/T1134
          MetricValue: "1"

  # Step 2: Create alarm for elevated process creation
  ElevatedProcessAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1134-ElevatedTokenProcess
      AlarmDescription: Process created with elevated token detected
      MetricName: ElevatedTokenProcess
      Namespace: Security/T1134
      Statistic: Sum
      Period: 900
      EvaluationPeriods: 1
      Threshold: 3
      ComparisonOperator: GreaterThanThreshold
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref SNSTopicArn

  # Step 3: Monitor processes with mismatched user contexts
  UserMismatchFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudWatchLogGroup
      FilterPattern: '[EventID="4688", SubjectUser, TargetUser, condition=SubjectUser!=TargetUser]'
      MetricTransformations:
        - MetricName: UserContextMismatch
          MetricNamespace: Security/T1134
          MetricValue: "1"''',
                terraform_template="""# Detect process creation with token anomalies

variable "cloudwatch_log_group" {
  type        = string
  description = "Log group containing Windows Event logs"
  default     = "/aws/ec2/windows/security"
}

variable "alert_email" {
  type = string
}

resource "aws_sns_topic" "alerts" {
  name = "token-anomaly-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 1: Monitor processes created with elevated tokens
resource "aws_cloudwatch_log_metric_filter" "elevated_token_process" {
  name           = "elevated-token-process"
  log_group_name = var.cloudwatch_log_group
  pattern        = "[EventID=\"4688\", TokenType=\"%%1937\"]"

  metric_transformation {
    name      = "ElevatedTokenProcess"
    namespace = "Security/T1134"
    value     = "1"
  }
}

# Step 2: Create alarm for elevated process creation
resource "aws_cloudwatch_metric_alarm" "elevated_process" {
  alarm_name          = "T1134-ElevatedTokenProcess"
  alarm_description   = "Process created with elevated token detected"
  metric_name         = "ElevatedTokenProcess"
  namespace           = "Security/T1134"
  statistic           = "Sum"
  period              = 900
  evaluation_periods  = 1
  threshold           = 3
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}

# Step 3: Monitor processes with mismatched user contexts
resource "aws_cloudwatch_log_metric_filter" "user_context_mismatch" {
  name           = "user-context-mismatch"
  log_group_name = var.cloudwatch_log_group
  pattern        = "[EventID=\"4688\", SubjectUser, TargetUser, condition=SubjectUser!=TargetUser]"

  metric_transformation {
    name      = "UserContextMismatch"
    namespace = "Security/T1134"
    value     = "1"
  }
}""",
                alert_severity="high",
                alert_title="Process Created with Token Anomaly",
                alert_description_template=(
                    "Suspicious process creation detected on {computer}. "
                    "Process: {new_process_name}. Parent: {parent_process_name}. "
                    "Token elevation or user context mismatch detected."
                ),
                investigation_steps=[
                    "Review the process creation event details and token elevation type",
                    "Verify if the parent process legitimately creates elevated child processes",
                    "Check if the subject user and target user should differ",
                    "Examine the full process tree for suspicious relationships",
                    "Review what privileges were assigned to the new process",
                    "Check if the process matches known token manipulation patterns",
                    "Investigate other processes created by the same parent around the same time",
                ],
                containment_actions=[
                    "Terminate the suspicious process and its parent process",
                    "Review and revoke any privileges granted during the session",
                    "Force logout the user account if a specific user is involved",
                    "Isolate the instance to prevent lateral movement",
                    "Review Task Scheduler and startup locations for persistence",
                    "Check for new user accounts or modified group memberships",
                    "Rebuild the instance if token manipulation is confirmed",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal administrative processes that use runas or Task Scheduler; whitelist known legitimate parent-child process relationships",
            detection_coverage="60% - detects anomalous process creation patterns indicative of token manipulation",
            evasion_considerations="Attackers may create processes that mimic legitimate administrative workflows",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$10-25",
            prerequisites=[
                "Windows Advanced Audit Policy configured for Process Creation (4688)",
                "Process command-line logging enabled",
                "CloudWatch Agent configured to forward Security Event logs",
            ],
        ),
    ],
    recommended_order=[
        "t1134-guardduty-runtime",
        "t1134-tool-detection",
        "t1134-windows-events",
        "t1134-process-anomalies",
        "t1134-gcp-detection",
    ],
    total_effort_hours=9.5,
    coverage_improvement="+25% improvement for Defence Evasion and Privilege Escalation tactics",
)
