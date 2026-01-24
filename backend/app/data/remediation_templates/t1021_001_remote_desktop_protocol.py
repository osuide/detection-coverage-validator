"""
T1021.001 - Remote Services: Remote Desktop Protocol

Adversaries use Remote Desktop Protocol (RDP) to move laterally within
an environment. RDP is commonly enabled on Windows systems and can be
abused with valid credentials or through brute force attacks.

Detection Strategy:
- Monitor for RDP brute force attempts via failed login events
- Detect unusual RDP sessions from unexpected sources
- Track RDP-enabled ports and network connections
- Use Azure Bastion or Just-in-Time access for secure RDP

Used by APT29, Scattered Spider, FIN7, Conti, LockBit.
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
    technique_id="T1021.001",
    technique_name="Remote Services: Remote Desktop Protocol",
    tactic_ids=["TA0008"],
    mitre_url="https://attack.mitre.org/techniques/T1021/001/",
    threat_context=ThreatContext(
        description=(
            "Adversaries use Remote Desktop Protocol (RDP) to move laterally "
            "within environments. RDP provides interactive graphical access to "
            "Windows systems, allowing attackers to control compromised hosts "
            "and access sensitive data."
        ),
        attacker_goal="Gain interactive remote access to Windows systems for lateral movement",
        why_technique=[
            "RDP is enabled by default on many Windows systems",
            "Provides full interactive GUI access",
            "Works with valid credentials or brute force",
            "Often exposed to the internet on port 3389",
            "Difficult to distinguish from legitimate admin activity",
        ],
        known_threat_actors=[],
        recent_campaigns=[],
        prevalence="very_common",
        trend="stable",
        severity_score=8,
        severity_reasoning=(
            "RDP provides complete interactive control of compromised systems. "
            "Commonly exploited in ransomware attacks and lateral movement."
        ),
        business_impact=[
            "Complete system compromise",
            "Lateral movement across network",
            "Data exfiltration capability",
            "Ransomware deployment vector",
        ],
        typical_attack_phase="lateral_movement",
        often_precedes=["T1570", "T1486", "T1005"],
        often_follows=["T1078", "T1110", "T1133"],
    ),
    detection_strategies=[
        # AWS Strategy: VPC Flow Logs for RDP
        DetectionStrategy(
            strategy_id="t1021001-aws-flowlogs",
            name="AWS VPC Flow Logs RDP Detection",
            description="Detect RDP traffic patterns via VPC Flow Logs.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, srcAddr, dstAddr, dstPort, action
| filter dstPort = 3389
| filter action = "ACCEPT"
| stats count(*) as connection_count by srcAddr, dstAddr, bin(1h)
| filter connection_count > 10
| sort connection_count desc""",
                terraform_template="""# Detect RDP connections via VPC Flow Logs

variable "vpc_flow_log_group" {
  type        = string
  description = "CloudWatch Log Group for VPC Flow Logs"
}

variable "alert_email" {
  type        = string
  description = "Email for RDP security alerts"
}

# SNS Topic for alerts
resource "aws_sns_topic" "rdp_alerts" {
  name              = "rdp-connection-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.rdp_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Metric filter for RDP connections
resource "aws_cloudwatch_log_metric_filter" "rdp_connections" {
  name           = "rdp-connections"
  log_group_name = var.vpc_flow_log_group
  pattern        = "[version, account_id, interface_id, srcaddr, dstaddr, srcport, dstport=3389, protocol, packets, bytes, start, end, action=ACCEPT, log_status]"

  metric_transformation {
    name      = "RDPConnections"
    namespace = "Security"
    value     = "1"
  }
}

# Alarm for high RDP connection volume
resource "aws_cloudwatch_metric_alarm" "rdp_volume" {
  alarm_name          = "HighRDPConnections"
  metric_name         = "RDPConnections"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 50
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.rdp_alerts.arn]
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.rdp_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchAlarms"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.rdp_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="High Volume RDP Connections Detected",
                alert_description_template="Unusual RDP connection volume from {srcAddr} to {dstAddr}.",
                investigation_steps=[
                    "Identify source IP and verify if authorised",
                    "Check if RDP should be exposed on this instance",
                    "Review successful vs failed connection attempts",
                    "Check for lateral movement after RDP session",
                ],
                containment_actions=[
                    "Block source IP at Security Group or NACL",
                    "Disable RDP if not required",
                    "Enable AWS Systems Manager Session Manager as alternative",
                    "Implement Just-in-Time access",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Allowlist known admin IPs and jump hosts",
            detection_coverage="80% - catches RDP network traffic",
            evasion_considerations="RDP over non-standard ports not detected",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-15 (VPC Flow Logs)",
            prerequisites=["VPC Flow Logs enabled"],
        ),
        # AWS Strategy: GuardDuty RDP Detection
        DetectionStrategy(
            strategy_id="t1021001-aws-guardduty",
            name="AWS GuardDuty RDP Brute Force Detection",
            description=(
                "Leverage GuardDuty to detect RDP brute force attacks. "
                "See: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html"
            ),
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "UnauthorizedAccess:EC2/RDPBruteForce",
                ],
                terraform_template="""# GuardDuty RDP Brute Force Detection

variable "alert_email" {
  type        = string
  description = "Email for RDP security alerts"
}

# SNS Topic for alerts
resource "aws_sns_topic" "rdp_alerts" {
  name              = "guardduty-rdp-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.rdp_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Enable GuardDuty
resource "aws_guardduty_detector" "main" {
  enable = true
}

# EventBridge rule for RDP findings
resource "aws_cloudwatch_event_rule" "rdp_findings" {
  name        = "guardduty-rdp-findings"
  description = "Detect RDP brute force attacks"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [
        { prefix = "UnauthorizedAccess:EC2/RDPBruteForce" }
      ]
    }
  })
}

resource "aws_sqs_queue" "dlq" {
  name                      = "rdp-findings-dlq"
  message_retention_seconds = 1209600
}

resource "aws_cloudwatch_event_target" "to_sns" {
  rule      = aws_cloudwatch_event_rule.rdp_findings.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.rdp_alerts.arn

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
      "GuardDuty RDP Brute Force Alert (T1021.001)"
      "Type: <findingType>"
      "Severity: <severity>"
      "Instance: <instanceId>"
      "Account: <accountId> Region: <region>"
      "Action: Investigate RDP attack and consider blocking source IP"
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
          "aws:SourceArn" = aws_cloudwatch_event_rule.rdp_findings.arn
        }
      }
    }]
  })
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.rdp_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowEventBridgePublish"
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.rdp_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.rdp_findings.arn
        }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="GuardDuty: RDP Brute Force Attack Detected",
                alert_description_template=(
                    "GuardDuty detected RDP brute force attack: {type}. "
                    "Target instance: {instanceId}."
                ),
                investigation_steps=[
                    "Review GuardDuty finding details for attacker IP",
                    "Check if instance has RDP publicly exposed",
                    "Review Windows Security Event logs for 4625 events",
                    "Determine if any login was successful",
                ],
                containment_actions=[
                    "Block attacker IP at Security Group or NACL",
                    "Close RDP port 3389 from internet",
                    "Enable Network Level Authentication (NLA)",
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
        # GCP Strategy: RDP Detection via Firewall Logs
        DetectionStrategy(
            strategy_id="t1021001-gcp-firewall",
            name="GCP Firewall Logs RDP Detection",
            description="Detect RDP connections via GCP Firewall Logs.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gce_subnetwork"
logName:"compute.googleapis.com%2Ffirewall"
jsonPayload.connection.dest_port=3389
jsonPayload.disposition="ALLOWED"''',
                gcp_terraform_template="""# GCP: Detect RDP connections via Firewall Logs

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
  display_name = "RDP Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Log-based metric for RDP connections
resource "google_logging_metric" "rdp_connections" {
  project = var.project_id
  name    = "rdp-connection-attempts"
  filter  = <<-EOT
    resource.type="gce_subnetwork"
    logName:"compute.googleapis.com%2Ffirewall"
    jsonPayload.connection.dest_port=3389
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Alert policy for RDP attempts
resource "google_monitoring_alert_policy" "rdp_alert" {
  project      = var.project_id
  display_name = "RDP Connection Attempts"
  combiner     = "OR"

  conditions {
    display_name = "High volume RDP connections"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.rdp_connections.name}\""
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
                alert_title="GCP: RDP Connection Attempts Detected",
                alert_description_template="High volume of RDP connection attempts detected.",
                investigation_steps=[
                    "Review source IPs attempting RDP",
                    "Check if RDP port should be open",
                    "Review instance for compromise indicators",
                    "Check Windows Event Logs if accessible",
                ],
                containment_actions=[
                    "Update firewall rules to block RDP",
                    "Use IAP (Identity-Aware Proxy) for RDP",
                    "Enable OS Login for centralised access",
                    "Review and rotate credentials",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Allowlist known admin IP ranges",
            detection_coverage="75% - catches RDP network traffic",
            evasion_considerations="Non-standard ports not detected",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-20",
            prerequisites=["Firewall logging enabled"],
        ),
        # Azure Strategy: RDP Brute Force Detection
        DetectionStrategy(
            strategy_id="t1021001-azure",
            name="Azure RDP Brute Force Detection",
            description=(
                "Detect RDP brute force attacks using Windows Security Events "
                "and Microsoft Defender for Servers. Monitors Event ID 4625 "
                "(failed logon) with LogonType 10 (RemoteInteractive/RDP)."
            ),
            detection_type=DetectionType.LOG_ANALYTICS_QUERY,
            aws_service="n/a",
            azure_service="log_analytics",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                azure_kql_query="""// RDP Brute Force Detection
// Technique: T1021.001
// Monitors failed RDP login attempts (Event ID 4625, LogonType 10)
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4625
| where LogonType == 10  // RemoteInteractive (RDP)
| summarize
    FailedAttempts = count(),
    DistinctAccounts = dcount(TargetAccount),
    Accounts = make_set(TargetAccount, 10)
    by SourceIP = IpAddress, Computer, bin(TimeGenerated, 5m)
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
    DistinctAccounts,
    Accounts,
    Severity
| order by FailedAttempts desc""",
                azure_activity_operations=[
                    "SecurityEvent/4625/LogonType10",
                ],
                defender_alert_types=[
                    "VM.Windows_RDPBruteForce",
                ],
                azure_terraform_template="""# Azure Detection for RDP Brute Force
# MITRE ATT&CK: T1021.001
# Requires: Microsoft Defender for Servers or Security Events data connector

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
resource "azurerm_monitor_action_group" "rdp_alerts" {
  name                = "rdp-brute-force-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "RDPAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Scheduled Query Rule for RDP brute force detection
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "rdp_brute_force" {
  name                = "rdp-brute-force-detection"
  resource_group_name = var.resource_group_name
  location            = "uksouth"

  evaluation_frequency = "PT5M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 1  # Critical

  criteria {
    query = <<-QUERY
// RDP Brute Force Detection - T1021.001
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4625
| where LogonType == 10
| summarize
    FailedAttempts = count(),
    DistinctAccounts = dcount(TargetAccount),
    Accounts = make_set(TargetAccount, 10)
    by SourceIP = IpAddress, Computer, bin(TimeGenerated, 5m)
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
    action_groups = [azurerm_monitor_action_group.rdp_alerts.id]
  }

  description  = "Detects RDP brute force attacks (T1021.001) by monitoring failed logon events"
  display_name = "RDP Brute Force Attack Detection"
  enabled      = true

  tags = {
    "mitre-technique" = "T1021.001"
    "mitre-tactic"    = "TA0008"
    "detection-type"  = "security"
  }
}

# Additional rule for successful RDP after failed attempts
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "rdp_success_after_failure" {
  name                = "rdp-success-after-brute-force"
  resource_group_name = var.resource_group_name
  location            = "uksouth"

  evaluation_frequency = "PT5M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 0  # Critical - potential compromise

  criteria {
    query = <<-QUERY
// Detect successful RDP login after brute force attempts
let FailedRDP = SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4625 and LogonType == 10
| summarize FailedCount = count() by SourceIP = IpAddress, Computer
| where FailedCount > 5;
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4624 and LogonType == 10
| join kind=inner FailedRDP on $left.IpAddress == $right.SourceIP, Computer
| project TimeGenerated, Computer, TargetAccount, SourceIP, FailedCount
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
    action_groups = [azurerm_monitor_action_group.rdp_alerts.id]
  }

  description  = "Detects successful RDP login following brute force attempts - potential compromise"
  display_name = "RDP Success After Brute Force - Potential Compromise"
  enabled      = true

  tags = {
    "mitre-technique" = "T1021.001"
    "mitre-tactic"    = "TA0008"
    "detection-type"  = "security"
    "severity"        = "critical"
  }
}

output "rdp_brute_force_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.rdp_brute_force.id
}

output "rdp_success_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.rdp_success_after_failure.id
}""",
                alert_severity="critical",
                alert_title="Azure: RDP Brute Force Attack Detected",
                alert_description_template=(
                    "RDP brute force attack detected. "
                    "Source IP: {SourceIP}. Target: {Computer}. "
                    "Failed attempts: {FailedAttempts}."
                ),
                investigation_steps=[
                    "Review source IP reputation and geolocation",
                    "Check if source IP is known/expected (admin, jump host)",
                    "Review targeted accounts for sensitivity",
                    "Check for successful login following failed attempts",
                    "Review NSG rules - RDP should not be open to internet",
                    "Check Azure Bastion or Just-in-Time access logs",
                ],
                containment_actions=[
                    "Block source IP in NSG or Azure Firewall",
                    "Disable RDP access from internet immediately",
                    "Enable Azure Bastion for secure RDP access",
                    "Enable Just-in-Time VM access in Defender for Cloud",
                    "Reset passwords for targeted accounts",
                    "Enable Network Level Authentication (NLA)",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning=(
                "Allowlist known admin IPs and Azure Bastion ranges. "
                "Adjust threshold based on environment baseline. "
                "Exclude service accounts that use RDP for automation."
            ),
            detection_coverage="95% - Security Events provide comprehensive RDP visibility",
            evasion_considerations=(
                "Slow and distributed attacks may evade threshold-based detection. "
                "Combine with Defender for Servers for ML-based anomaly detection. "
                "Monitor for RDP over non-standard ports."
            ),
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes - 1 hour",
            estimated_monthly_cost=(
                "Log Analytics: ~$2.30/GB ingested. "
                "Defender for Servers: ~$15/server/month. "
                "See: https://azure.microsoft.com/pricing/details/monitor/"
            ),
            prerequisites=[
                "Log Analytics workspace with SecurityEvent table",
                "Windows Security Events data connector enabled",
                "Microsoft Defender for Servers (recommended)",
                "Network Security Groups configured",
            ],
        ),
    ],
    recommended_order=[
        "t1021001-aws-guardduty",
        "t1021001-azure",
        "t1021001-aws-flowlogs",
        "t1021001-gcp-firewall",
    ],
    total_effort_hours=3.0,
    coverage_improvement="+12% improvement for Lateral Movement tactic",
)
