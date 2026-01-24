"""
T1021.004 - Remote Services: SSH

Adversaries use Secure Shell (SSH) to move laterally within environments.
SSH provides encrypted remote access to Linux/Unix systems and is commonly
targeted through brute force attacks or credential theft.

Detection Strategy:
- Monitor for SSH brute force attempts via auth logs
- Detect unusual SSH sessions from unexpected sources
- Track SSH key usage and authentication patterns
- Use Azure Bastion or session recording for secure SSH

Used by APT29, APT41, TeamTNT, Outlaw, Rocke.
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
    technique_id="T1021.004",
    technique_name="Remote Services: SSH",
    tactic_ids=["TA0008"],
    mitre_url="https://attack.mitre.org/techniques/T1021/004/",
    threat_context=ThreatContext(
        description=(
            "Adversaries use SSH to move laterally within environments. "
            "SSH provides encrypted command-line access to Linux/Unix systems, "
            "allowing attackers to execute commands, transfer files, and pivot "
            "to other systems using stolen credentials or keys."
        ),
        attacker_goal="Gain remote command-line access to Linux/Unix systems for lateral movement",
        why_technique=[
            "SSH is ubiquitous on Linux/Unix systems",
            "Encrypted traffic hides command execution",
            "SSH keys enable passwordless access",
            "Port 22 often exposed externally",
            "Enables tunnelling and port forwarding",
        ],
        known_threat_actors=[],
        recent_campaigns=[],
        prevalence="very_common",
        trend="stable",
        severity_score=8,
        severity_reasoning=(
            "SSH provides complete command-line control of compromised systems. "
            "Commonly exploited in cryptomining attacks and lateral movement."
        ),
        business_impact=[
            "Complete system compromise",
            "Lateral movement across network",
            "Data exfiltration capability",
            "Cryptomining deployment vector",
        ],
        typical_attack_phase="lateral_movement",
        often_precedes=["T1570", "T1496.001", "T1005"],
        often_follows=["T1078", "T1110", "T1552.004"],
    ),
    detection_strategies=[
        # AWS Strategy: VPC Flow Logs for SSH
        DetectionStrategy(
            strategy_id="t1021004-aws-flowlogs",
            name="AWS VPC Flow Logs SSH Detection",
            description="Detect SSH traffic patterns via VPC Flow Logs.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, srcAddr, dstAddr, dstPort, action
| filter dstPort = 22
| filter action = "ACCEPT"
| stats count(*) as connection_count by srcAddr, dstAddr, bin(1h)
| filter connection_count > 20
| sort connection_count desc""",
                terraform_template="""# Detect SSH connections via VPC Flow Logs

variable "vpc_flow_log_group" {
  type        = string
  description = "CloudWatch Log Group for VPC Flow Logs"
}

variable "alert_email" {
  type        = string
  description = "Email for SSH security alerts"
}

# SNS Topic for alerts
resource "aws_sns_topic" "ssh_alerts" {
  name              = "ssh-connection-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.ssh_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Metric filter for SSH connections
resource "aws_cloudwatch_log_metric_filter" "ssh_connections" {
  name           = "ssh-connections"
  log_group_name = var.vpc_flow_log_group
  pattern        = "[version, account_id, interface_id, srcaddr, dstaddr, srcport, dstport=22, protocol, packets, bytes, start, end, action=ACCEPT, log_status]"

  metric_transformation {
    name      = "SSHConnections"
    namespace = "Security"
    value     = "1"
  }
}

# Alarm for high SSH connection volume
resource "aws_cloudwatch_metric_alarm" "ssh_volume" {
  alarm_name          = "HighSSHConnections"
  metric_name         = "SSHConnections"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 100
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.ssh_alerts.arn]
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.ssh_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchAlarms"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.ssh_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="High Volume SSH Connections Detected",
                alert_description_template="Unusual SSH connection volume from {srcAddr} to {dstAddr}.",
                investigation_steps=[
                    "Identify source IP and verify if authorised",
                    "Check if SSH should be exposed on this instance",
                    "Review auth logs for failed/successful attempts",
                    "Check for lateral movement after SSH session",
                ],
                containment_actions=[
                    "Block source IP at Security Group or NACL",
                    "Disable password authentication, use key-only",
                    "Implement AWS Systems Manager Session Manager",
                    "Enable fail2ban or similar rate limiting",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Allowlist known admin IPs and bastion hosts",
            detection_coverage="80% - catches SSH network traffic",
            evasion_considerations="SSH over non-standard ports not detected",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-15 (VPC Flow Logs)",
            prerequisites=["VPC Flow Logs enabled"],
        ),
        # AWS Strategy: GuardDuty SSH Detection
        DetectionStrategy(
            strategy_id="t1021004-aws-guardduty",
            name="AWS GuardDuty SSH Brute Force Detection",
            description=(
                "Leverage GuardDuty to detect SSH brute force attacks. "
                "See: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html"
            ),
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "UnauthorizedAccess:EC2/SSHBruteForce",
                ],
                terraform_template="""# GuardDuty SSH Brute Force Detection

variable "alert_email" {
  type        = string
  description = "Email for SSH security alerts"
}

# SNS Topic for alerts
resource "aws_sns_topic" "ssh_alerts" {
  name              = "guardduty-ssh-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.ssh_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Enable GuardDuty
resource "aws_guardduty_detector" "main" {
  enable = true
}

# EventBridge rule for SSH findings
resource "aws_cloudwatch_event_rule" "ssh_findings" {
  name        = "guardduty-ssh-findings"
  description = "Detect SSH brute force attacks"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [
        { prefix = "UnauthorizedAccess:EC2/SSHBruteForce" }
      ]
    }
  })
}

resource "aws_sqs_queue" "dlq" {
  name                      = "ssh-findings-dlq"
  message_retention_seconds = 1209600
}

resource "aws_cloudwatch_event_target" "to_sns" {
  rule      = aws_cloudwatch_event_rule.ssh_findings.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.ssh_alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
  }

  input_transformer {
    input_paths = {
      findingType = "$.detail.type"
      severity    = "$.detail.severity"
      accountId   = "$.account"
      region      = "$.region"
      instanceId  = "$.detail.resource.instanceDetails.instanceId"
    }
    input_template = <<-EOF
      "GuardDuty SSH Brute Force Alert (T1021.004)"
      "Type: <findingType>"
      "Severity: <severity>"
      "Instance: <instanceId>"
      "Account: <accountId> Region: <region>"
      "Action: Investigate SSH attack and consider blocking source IP"
    EOF
  }
}

resource "aws_sqs_queue_policy" "dlq_policy" {
  queue_url = aws_sqs_queue.dlq.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.dlq.arn
      Condition = {
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.ssh_findings.arn
        }
      }
    }]
  })
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.ssh_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowEventBridgePublish"
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.ssh_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.ssh_findings.arn
        }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="GuardDuty: SSH Brute Force Attack Detected",
                alert_description_template=(
                    "GuardDuty detected SSH brute force attack: {type}. "
                    "Target instance: {instanceId}."
                ),
                investigation_steps=[
                    "Review GuardDuty finding details for attacker IP",
                    "Check if instance has SSH publicly exposed",
                    "Review /var/log/auth.log or /var/log/secure",
                    "Determine if any login was successful",
                ],
                containment_actions=[
                    "Block attacker IP at Security Group or NACL",
                    "Close SSH port 22 from internet",
                    "Disable password authentication",
                    "Implement AWS Systems Manager Session Manager",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="GuardDuty ML-based detection reduces false positives",
            detection_coverage="90% - ML-based brute force detection",
            evasion_considerations="Slow/distributed attacks may evade",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$4/GB analysed",
            prerequisites=["GuardDuty enabled"],
        ),
        # GCP Strategy: SSH Detection via Syslog
        DetectionStrategy(
            strategy_id="t1021004-gcp-syslog",
            name="GCP SSH Detection via Cloud Logging",
            description="Detect SSH authentication attempts via syslog forwarding.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gce_instance"
logName:"syslog"
textPayload=~"(Failed password|Invalid user|Accepted publickey)"''',
                gcp_terraform_template="""# GCP: Detect SSH attempts via Cloud Logging

variable "project_id" {
  type        = string
  description = "GCP Project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Notification channel
resource "google_monitoring_notification_channel" "email" {
  project      = var.project_id
  display_name = "SSH Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Log-based metric for failed SSH attempts
resource "google_logging_metric" "ssh_failed" {
  project = var.project_id
  name    = "ssh-failed-attempts"
  filter  = <<-EOT
    resource.type="gce_instance"
    logName:"syslog"
    textPayload=~"Failed password|Invalid user"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Alert policy for SSH brute force
resource "google_monitoring_alert_policy" "ssh_brute_force" {
  project      = var.project_id
  display_name = "SSH Brute Force Detection"
  combiner     = "OR"

  conditions {
    display_name = "High volume failed SSH attempts"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.ssh_failed.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 20
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }
}""",
                alert_severity="high",
                alert_title="GCP: SSH Brute Force Detected",
                alert_description_template="High volume of failed SSH authentication attempts detected.",
                investigation_steps=[
                    "Review source IPs attempting SSH",
                    "Check if SSH port should be open",
                    "Review instance auth logs",
                    "Check for successful logins after failures",
                ],
                containment_actions=[
                    "Update firewall rules to block SSH from untrusted sources",
                    "Use IAP (Identity-Aware Proxy) for SSH",
                    "Enable OS Login for centralised access",
                    "Disable password authentication",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Allowlist known admin IP ranges",
            detection_coverage="85% - catches SSH auth events",
            evasion_considerations="Key-based attacks without failures not detected",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-20",
            prerequisites=["Syslog forwarding to Cloud Logging"],
        ),
        # Azure Strategy: SSH Brute Force Detection
        DetectionStrategy(
            strategy_id="t1021004-azure",
            name="Azure SSH Brute Force Detection",
            description=(
                "Detect SSH brute force attacks using Linux Syslog data "
                "forwarded to Log Analytics. Monitors authentication failures "
                "from /var/log/auth.log or /var/log/secure."
            ),
            detection_type=DetectionType.LOG_ANALYTICS_QUERY,
            aws_service="n/a",
            azure_service="log_analytics",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                azure_kql_query="""// SSH Brute Force Detection
// Technique: T1021.004
// Monitors failed SSH login attempts via Syslog
Syslog
| where TimeGenerated > ago(1h)
| where Facility == "auth" or Facility == "authpriv"
| where SyslogMessage contains "Failed password" or SyslogMessage contains "Invalid user"
| parse SyslogMessage with * "from " SourceIP " port" *
| summarize
    FailedAttempts = count(),
    DistinctUsers = dcount(extract("for (invalid user )?([^ ]+)", 2, SyslogMessage)),
    Users = make_set(extract("for (invalid user )?([^ ]+)", 2, SyslogMessage), 10)
    by SourceIP, Computer, bin(TimeGenerated, 5m)
| where FailedAttempts > 10
| extend
    Severity = case(
        FailedAttempts > 100, "Critical",
        FailedAttempts > 50, "High",
        FailedAttempts > 20, "Medium",
        "Low"
    )
| project
    TimeGenerated,
    Computer,
    SourceIP,
    FailedAttempts,
    DistinctUsers,
    Users,
    Severity
| order by FailedAttempts desc""",
                azure_activity_operations=[
                    "Syslog/auth/FailedPassword",
                ],
                defender_alert_types=[
                    "VM.Linux_SSHBruteForce",
                ],
                azure_terraform_template="""# Azure Detection for SSH Brute Force
# MITRE ATT&CK: T1021.004
# Requires: Log Analytics agent or Azure Monitor Agent with Syslog collection

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
resource "azurerm_monitor_action_group" "ssh_alerts" {
  name                = "ssh-brute-force-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "SSHAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Scheduled Query Rule for SSH brute force detection
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "ssh_brute_force" {
  name                = "ssh-brute-force-detection"
  resource_group_name = var.resource_group_name
  location            = "uksouth"

  evaluation_frequency = "PT5M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 1  # Critical

  criteria {
    query = <<-QUERY
// SSH Brute Force Detection - T1021.004
Syslog
| where TimeGenerated > ago(1h)
| where Facility == "auth" or Facility == "authpriv"
| where SyslogMessage contains "Failed password" or SyslogMessage contains "Invalid user"
| parse SyslogMessage with * "from " SourceIP " port" *
| summarize
    FailedAttempts = count(),
    DistinctUsers = dcount(extract("for (invalid user )?([^ ]+)", 2, SyslogMessage))
    by SourceIP, Computer, bin(TimeGenerated, 5m)
| where FailedAttempts > 10
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
    action_groups = [azurerm_monitor_action_group.ssh_alerts.id]
  }

  description  = "Detects SSH brute force attacks (T1021.004) by monitoring failed authentication events"
  display_name = "SSH Brute Force Attack Detection"
  enabled      = true

  tags = {
    "mitre-technique" = "T1021.004"
    "mitre-tactic"    = "TA0008"
    "detection-type"  = "security"
  }
}

# Additional rule for successful SSH after failed attempts
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "ssh_success_after_failure" {
  name                = "ssh-success-after-brute-force"
  resource_group_name = var.resource_group_name
  location            = "uksouth"

  evaluation_frequency = "PT5M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 0  # Critical - potential compromise

  criteria {
    query = <<-QUERY
// Detect successful SSH login after brute force attempts
let FailedSSH = Syslog
| where TimeGenerated > ago(1h)
| where Facility in ("auth", "authpriv")
| where SyslogMessage contains "Failed password"
| parse SyslogMessage with * "from " SourceIP " port" *
| summarize FailedCount = count() by SourceIP, Computer
| where FailedCount > 5;
Syslog
| where TimeGenerated > ago(1h)
| where Facility in ("auth", "authpriv")
| where SyslogMessage contains "Accepted"
| parse SyslogMessage with * "from " SourceIP " port" *
| join kind=inner FailedSSH on SourceIP, Computer
| parse SyslogMessage with * "for " User " from" *
| project TimeGenerated, Computer, User, SourceIP, FailedCount
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
    action_groups = [azurerm_monitor_action_group.ssh_alerts.id]
  }

  description  = "Detects successful SSH login following brute force attempts - potential compromise"
  display_name = "SSH Success After Brute Force - Potential Compromise"
  enabled      = true

  tags = {
    "mitre-technique" = "T1021.004"
    "mitre-tactic"    = "TA0008"
    "detection-type"  = "security"
    "severity"        = "critical"
  }
}

output "ssh_brute_force_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.ssh_brute_force.id
}

output "ssh_success_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.ssh_success_after_failure.id
}""",
                alert_severity="critical",
                alert_title="Azure: SSH Brute Force Attack Detected",
                alert_description_template=(
                    "SSH brute force attack detected. "
                    "Source IP: {SourceIP}. Target: {Computer}. "
                    "Failed attempts: {FailedAttempts}."
                ),
                investigation_steps=[
                    "Review source IP reputation and geolocation",
                    "Check if source IP is known/expected (admin, bastion)",
                    "Review targeted usernames for sensitivity",
                    "Check for successful login following failed attempts",
                    "Review NSG rules - SSH should not be open to internet",
                    "Check Azure Bastion or Just-in-Time access logs",
                ],
                containment_actions=[
                    "Block source IP in NSG or Azure Firewall",
                    "Disable SSH access from internet immediately",
                    "Enable Azure Bastion for secure SSH access",
                    "Enable Just-in-Time VM access in Defender for Cloud",
                    "Disable password authentication, use key-only",
                    "Review and rotate SSH keys if compromised",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning=(
                "Allowlist known admin IPs and Azure Bastion ranges. "
                "Adjust threshold based on environment baseline. "
                "Exclude service accounts that use SSH for automation."
            ),
            detection_coverage="90% - Syslog provides comprehensive SSH visibility",
            evasion_considerations=(
                "Slow and distributed attacks may evade threshold-based detection. "
                "Combine with Defender for Servers for ML-based anomaly detection. "
                "Key-based authentication without failures harder to detect."
            ),
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes - 1 hour",
            estimated_monthly_cost=(
                "Log Analytics: ~$2.30/GB ingested. "
                "Defender for Servers: ~$15/server/month. "
                "See: https://azure.microsoft.com/pricing/details/monitor/"
            ),
            prerequisites=[
                "Log Analytics workspace with Syslog table",
                "Azure Monitor Agent or Log Analytics agent installed",
                "Syslog collection configured (auth/authpriv facilities)",
                "Microsoft Defender for Servers (recommended)",
            ],
        ),
    ],
    recommended_order=[
        "t1021004-aws-guardduty",
        "t1021004-azure",
        "t1021004-aws-flowlogs",
        "t1021004-gcp-syslog",
    ],
    total_effort_hours=3.0,
    coverage_improvement="+12% improvement for Lateral Movement tactic",
)
