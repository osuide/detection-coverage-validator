"""
T1505.003 - Server Software Component: Web Shell

Adversaries deploy web shells on compromised servers to maintain persistent
access. Web shells provide command execution through HTTP/HTTPS requests,
making them difficult to detect as they blend with normal web traffic.
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
    technique_id="T1505.003",
    technique_name="Server Software Component: Web Shell",
    tactic_ids=["TA0003"],
    mitre_url="https://attack.mitre.org/techniques/T1505/003/",
    threat_context=ThreatContext(
        description=(
            "Adversaries install web shells on compromised web servers to maintain "
            "persistent backdoor access. Web shells accept commands via HTTP requests "
            "and can execute arbitrary code, enabling data exfiltration, lateral movement, "
            "and further compromise. Common in Azure App Services, IIS, and container workloads."
        ),
        attacker_goal="Maintain persistent backdoor access to web servers via HTTP",
        why_technique=[
            "Blends with normal web traffic",
            "Survives service restarts",
            "Provides remote command execution",
            "Difficult to detect without file integrity monitoring",
            "Can be hidden in legitimate-looking files",
        ],
        known_threat_actors=["APT28", "APT34", "Hafnium", "Lazarus Group"],
        recent_campaigns=[],
        prevalence="common",
        trend="stable",
        severity_score=9,
        severity_reasoning=(
            "Web shells provide full command execution on compromised servers. "
            "They enable long-term persistent access and are frequently used in "
            "serious breaches including ransomware and data theft campaigns."
        ),
        business_impact=[
            "Persistent unauthorised access",
            "Data exfiltration",
            "Lateral movement within network",
            "Ransomware deployment",
            "Cryptomining abuse",
        ],
        typical_attack_phase="persistence",
        often_precedes=["T1059", "T1005", "T1570"],
        often_follows=["T1190", "T1133"],
    ),
    detection_strategies=[
        # =====================================================================
        # STRATEGY 1: Azure App Service Web Shell Detection
        # =====================================================================
        DetectionStrategy(
            strategy_id="t1505003-azure-appservice",
            name="Azure App Service Web Shell Detection",
            description=(
                "Detect web shell activity on Azure App Services by monitoring for "
                "suspicious HTTP requests, unusual file modifications, and command "
                "execution patterns in application logs."
            ),
            detection_type=DetectionType.SENTINEL_RULE,
            aws_service="n/a",
            azure_service="sentinel",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                azure_kql_query="""// Azure App Service Web Shell Detection
// MITRE ATT&CK: T1505.003 - Web Shell
// Detects suspicious HTTP patterns indicating web shell activity

let lookback = 1h;

// Detect suspicious URL patterns commonly used by web shells
AppServiceHTTPLogs
| where TimeGenerated > ago(lookback)
| where ScStatus == 200
| extend
    SuspiciousPath = CsUriStem matches regex @"(?i)\.(asp|aspx|php|jsp|jspx|cfm)$"
        and (
            CsUriQuery contains "cmd="
            or CsUriQuery contains "command="
            or CsUriQuery contains "c="
            or CsUriQuery contains "execute="
            or CsUriQuery contains "run="
            or CsUriQuery contains "code="
            or CsUriQuery contains "pass="
            or CsUriQuery contains "password="
        ),
    ShellIndicator = CsUriStem contains_any (
        "shell", "cmd", "backdoor", "upload", "filemanager",
        "c99", "r57", "b374k", "weevely", "chopper"
    ),
    UnusualMethod = CsMethod in ("PUT", "DELETE", "PATCH")
        and CsUriStem matches regex @"\.(asp|aspx|php|jsp|cfm|txt|tmp)$"
| where SuspiciousPath == true or ShellIndicator == true or UnusualMethod == true
| summarize
    RequestCount = count(),
    UniqueIPs = dcount(CIp),
    SourceIPs = make_set(CIp, 20),
    Paths = make_set(CsUriStem, 20),
    Queries = make_set(CsUriQuery, 10),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by _ResourceId, CsHost
| project
    TimeGenerated = LastSeen,
    ResourceId = _ResourceId,
    Host = CsHost,
    RequestCount,
    UniqueIPs,
    SourceIPs,
    Paths,
    Queries,
    FirstSeen""",
                sentinel_rule_query="""// Sentinel Analytics Rule: Web Shell Detection
// MITRE ATT&CK: T1505.003
let lookback = 24h;

// Combine HTTP logs with file change events for comprehensive detection
let SuspiciousRequests = AppServiceHTTPLogs
| where TimeGenerated > ago(lookback)
| extend
    IsWebShellPath = CsUriStem matches regex @"(?i)\.(asp|aspx|php|jsp|cfm)$"
        and (
            CsUriQuery contains "cmd"
            or CsUriQuery contains "exec"
            or CsUriQuery contains "command"
            or CsUriQuery contains "shell"
        ),
    IsKnownShellName = CsUriStem contains_any (
        "shell", "backdoor", "upload", "filemanager", "c99", "r57"
    )
| where IsWebShellPath == true or IsKnownShellName == true;

// Detect file creation events that may indicate web shell upload
let FileChanges = AppServiceFileAuditLogs
| where TimeGenerated > ago(lookback)
| where OperationName in ("Create", "Write")
| where Path matches regex @"(?i)\.(asp|aspx|php|jsp|cfm|txt)$"
| extend IsNewScript = true;

SuspiciousRequests
| summarize
    TotalRequests = count(),
    UniqueIPs = dcount(CIp),
    SourceIPs = make_set(CIp, 10),
    Paths = make_set(CsUriStem, 10),
    Queries = make_set(CsUriQuery, 5)
    by _ResourceId, CsHost, bin(TimeGenerated, 1h)
| where TotalRequests > 3
| project
    TimeGenerated,
    ResourceId = _ResourceId,
    Host = CsHost,
    TotalRequests,
    UniqueIPs,
    SourceIPs,
    Paths,
    Queries""",
                azure_terraform_template="""# Azure App Service Web Shell Detection
# MITRE ATT&CK: T1505.003

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

# Action Group for web shell alerts
resource "azurerm_monitor_action_group" "webshell_alerts" {
  name                = "webshell-detection-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "WebShell"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Scheduled Query Rule for web shell detection
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "webshell_detection" {
  name                = "appservice-webshell-detection"
  resource_group_name = var.resource_group_name
  location            = "uksouth"

  evaluation_frequency = "PT5M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 1

  criteria {
    query = <<-QUERY
AppServiceHTTPLogs
| where TimeGenerated > ago(1h)
| where ScStatus == 200
| extend
    SuspiciousPath = CsUriStem matches regex @"(?i)\.(asp|aspx|php|jsp|cfm)$"
        and (
            CsUriQuery contains "cmd"
            or CsUriQuery contains "command"
            or CsUriQuery contains "exec"
            or CsUriQuery contains "shell"
        ),
    ShellIndicator = CsUriStem contains_any (
        "shell", "backdoor", "upload", "c99", "r57"
    )
| where SuspiciousPath == true or ShellIndicator == true
| summarize RequestCount = count() by _ResourceId, CsHost, CIp
| where RequestCount > 3
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
    action_groups = [azurerm_monitor_action_group.webshell_alerts.id]
  }

  description  = "Detects web shell activity on Azure App Services"
  display_name = "Web Shell Detection - Azure App Service"
  enabled      = true

  tags = {
    "mitre-technique" = "T1505.003"
    "detection-type"  = "persistence"
    "severity"        = "critical"
  }
}

# Additional rule for file upload detection
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "webshell_upload" {
  name                = "appservice-webshell-upload"
  resource_group_name = var.resource_group_name
  location            = "uksouth"

  evaluation_frequency = "PT5M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 1

  criteria {
    query = <<-QUERY
AppServiceFileAuditLogs
| where TimeGenerated > ago(1h)
| where OperationName in ("Create", "Write")
| where Path matches regex @"(?i)\.(asp|aspx|php|jsp|cfm|txt)$"
| where Path !contains "node_modules"
| where Path !contains ".git"
| summarize
    FileCount = count(),
    Files = make_set(Path, 10)
    by _ResourceId, bin(TimeGenerated, 10m)
| where FileCount > 2
    QUERY

    time_aggregation_method = "Count"
    threshold               = 1
    operator                = "GreaterThanOrEqual"

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  action {
    action_groups = [azurerm_monitor_action_group.webshell_alerts.id]
  }

  description  = "Detects suspicious file uploads that may indicate web shell"
  display_name = "Web Shell Upload Detection"
  enabled      = true

  tags = {
    "mitre-technique" = "T1505.003"
  }
}

output "detection_rule_id" {
  value       = azurerm_monitor_scheduled_query_rules_alert_v2.webshell_detection.id
  description = "Web shell detection rule ID"
}

output "upload_rule_id" {
  value       = azurerm_monitor_scheduled_query_rules_alert_v2.webshell_upload.id
  description = "Web shell upload detection rule ID"
}""",
                alert_severity="critical",
                alert_title="Azure: Web Shell Activity Detected",
                alert_description_template=(
                    "Potential web shell activity detected on {Host}. "
                    "Suspicious paths: {Paths}. Source IPs: {SourceIPs}."
                ),
                investigation_steps=[
                    "Review AppServiceHTTPLogs for the suspicious requests",
                    "Check AppServiceFileAuditLogs for file modifications",
                    "Analyse the suspected web shell file content",
                    "Review deployment history for unauthorised changes",
                    "Check source IPs against threat intelligence",
                    "Review all requests from the source IPs",
                ],
                containment_actions=[
                    "Immediately take the App Service offline if confirmed",
                    "Remove the web shell file(s)",
                    "Block source IPs using Azure WAF or NSG",
                    "Rotate all deployment credentials",
                    "Review and patch the vulnerability exploited for access",
                    "Scan for additional backdoors using Defender for Cloud",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning=(
                "Allowlist legitimate file management endpoints. "
                "Exclude known admin IPs from alerting."
            ),
            detection_coverage="85% - Comprehensive HTTP and file-based detection",
            evasion_considerations=(
                "Encoded commands may evade string matching. "
                "Web shells in non-standard extensions need custom rules. "
                "Consider enabling Defender for App Service for ML-based detection."
            ),
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$15-40 (Log Analytics)",
            prerequisites=[
                "Azure App Service with HTTP logging enabled",
                "AppServiceFileAuditLogs enabled",
                "Log Analytics workspace",
            ],
        ),
        # =====================================================================
        # STRATEGY 2: Azure Defender for App Service
        # =====================================================================
        DetectionStrategy(
            strategy_id="t1505003-azure-defender",
            name="Microsoft Defender for App Service",
            description=(
                "Leverage Defender for App Service for ML-based web shell detection. "
                "Provides automated threat detection across Azure App Services with "
                "minimal configuration required."
            ),
            detection_type=DetectionType.DEFENDER_ALERT,
            aws_service="n/a",
            azure_service="defender",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                azure_kql_query="""// Defender for App Service Alerts - Web Shell Detection
// MITRE ATT&CK: T1505.003
SecurityAlert
| where TimeGenerated > ago(24h)
| where ProviderName == "Azure Security Center"
| where AlertType contains "AppServices" or AlertType contains "WebShell"
| extend
    TechniqueId = tostring(parse_json(ExtendedProperties).["MITRE ATT&CK Technique"]),
    ResourceId = tostring(parse_json(ExtendedProperties).ResourceId)
| where TechniqueId contains "T1505" or AlertName contains "shell"
| project
    TimeGenerated,
    AlertName,
    AlertSeverity,
    Description,
    RemediationSteps,
    ResourceId,
    TechniqueId,
    ExtendedProperties""",
                azure_terraform_template="""# Enable Defender for App Service
# MITRE ATT&CK: T1505.003 - Automated Detection

terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 3.0"
    }
  }
}

variable "subscription_id" {
  type        = string
  description = "Azure Subscription ID"
}

# Enable Defender for App Service
resource "azurerm_security_center_subscription_pricing" "appservices" {
  tier          = "Standard"
  resource_type = "AppServices"
}

# Enable auto-provisioning of Log Analytics agent
resource "azurerm_security_center_auto_provisioning" "auto" {
  auto_provision = "On"
}

# Security contact for alerts
resource "azurerm_security_center_contact" "security" {
  email               = var.alert_email
  phone               = var.security_phone
  alert_notifications = true
  alerts_to_admins    = true
}

variable "alert_email" {
  type        = string
  description = "Email for Defender alerts"
}

variable "security_phone" {
  type        = string
  default     = ""
  description = "Phone for critical alerts"
}

output "defender_status" {
  value       = azurerm_security_center_subscription_pricing.appservices.tier
  description = "Defender for App Service tier"
}""",
                alert_severity="critical",
                alert_title="Defender: Web Shell Detected on App Service",
                alert_description_template=(
                    "Microsoft Defender detected web shell activity: {AlertName}. "
                    "Resource: {ResourceId}."
                ),
                investigation_steps=[
                    "Review the Defender alert details in Azure Portal",
                    "Follow the RemediationSteps provided by Defender",
                    "Check the affected App Service for file modifications",
                    "Review access logs for the source of compromise",
                    "Analyse the detected web shell",
                ],
                containment_actions=[
                    "Follow Defender automated remediation recommendations",
                    "Take App Service offline if actively exploited",
                    "Quarantine affected resources",
                    "Rotate credentials and secrets",
                    "Engage incident response team",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning=(
                "Defender uses ML models with low false positive rates. "
                "Suppress alerts for known security testing tools."
            ),
            detection_coverage="90% - ML-based detection with minimal false positives",
            evasion_considerations=(
                "Novel web shells may initially evade ML detection. "
                "Combine with custom KQL rules for defence in depth."
            ),
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$15/App Service/month",
            prerequisites=[
                "Azure subscription",
                "Defender for Cloud enabled",
            ],
        ),
        # =====================================================================
        # STRATEGY 3: AWS WAF + CloudWatch Web Shell Detection
        # =====================================================================
        DetectionStrategy(
            strategy_id="t1505003-aws-waf",
            name="AWS WAF Web Shell Pattern Detection",
            description=(
                "Use AWS WAF managed rules and custom rules to detect and block "
                "web shell requests. Combined with CloudWatch for alerting."
            ),
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="waf",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                terraform_template="""# AWS WAF Web Shell Detection
# MITRE ATT&CK: T1505.003

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

variable "resource_arn" {
  type        = string
  description = "ARN of the resource to protect (ALB, API Gateway, CloudFront)"
}

# WAF Web ACL with web shell detection rules
resource "aws_wafv2_web_acl" "webshell_protection" {
  name        = "webshell-protection"
  description = "Detect and block web shell patterns"
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  # AWS Managed Rules - Common Rule Set
  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 1

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSManagedRulesCommonRuleSet"
      sampled_requests_enabled   = true
    }
  }

  # AWS Managed Rules - Known Bad Inputs
  rule {
    name     = "AWSManagedRulesKnownBadInputsRuleSet"
    priority = 2

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSManagedRulesKnownBadInputs"
      sampled_requests_enabled   = true
    }
  }

  # Custom rule for web shell patterns
  rule {
    name     = "WebShellPatternDetection"
    priority = 3

    action {
      block {}
    }

    statement {
      or_statement {
        statement {
          byte_match_statement {
            positional_constraint = "CONTAINS"
            search_string         = "cmd="
            field_to_match {
              query_string {}
            }
            text_transformation {
              priority = 0
              type     = "URL_DECODE"
            }
            text_transformation {
              priority = 1
              type     = "LOWERCASE"
            }
          }
        }
        statement {
          byte_match_statement {
            positional_constraint = "CONTAINS"
            search_string         = "shell"
            field_to_match {
              uri_path {}
            }
            text_transformation {
              priority = 0
              type     = "LOWERCASE"
            }
          }
        }
        statement {
          byte_match_statement {
            positional_constraint = "CONTAINS"
            search_string         = "backdoor"
            field_to_match {
              uri_path {}
            }
            text_transformation {
              priority = 0
              type     = "LOWERCASE"
            }
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "WebShellPatternDetection"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "webshell-protection-waf"
    sampled_requests_enabled   = true
  }
}

# Associate WAF with resource
resource "aws_wafv2_web_acl_association" "main" {
  resource_arn = var.resource_arn
  web_acl_arn  = aws_wafv2_web_acl.webshell_protection.arn
}

# SNS topic for alerts
resource "aws_sns_topic" "waf_alerts" {
  name              = "waf-webshell-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.waf_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# CloudWatch alarm for blocked requests
resource "aws_cloudwatch_metric_alarm" "webshell_blocked" {
  alarm_name          = "waf-webshell-blocked"
  alarm_description   = "WAF blocked potential web shell request"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "BlockedRequests"
  namespace           = "AWS/WAFV2"
  period              = 300
  statistic           = "Sum"
  threshold           = 5
  treat_missing_data  = "notBreaching"

  dimensions = {
    WebACL = aws_wafv2_web_acl.webshell_protection.name
    Rule   = "WebShellPatternDetection"
  }

  alarm_actions = [aws_sns_topic.waf_alerts.arn]
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.waf_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatch"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.waf_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}

output "web_acl_arn" {
  value       = aws_wafv2_web_acl.webshell_protection.arn
  description = "WAF Web ACL ARN"
}""",
                alert_severity="critical",
                alert_title="AWS WAF: Web Shell Pattern Blocked",
                alert_description_template=(
                    "WAF blocked potential web shell request. "
                    "Check WAF logs for details."
                ),
                investigation_steps=[
                    "Review WAF logs for the blocked request details",
                    "Identify the source IP and user agent",
                    "Check if the request was legitimate or attack",
                    "Review application logs for related activity",
                    "Scan the server for existing web shells",
                ],
                containment_actions=[
                    "Block source IP in WAF or security groups",
                    "Scan EC2 instances for web shell files",
                    "Review recent file changes on web servers",
                    "Rotate application credentials",
                    "Enable GuardDuty if not already active",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning=(
                "Add exceptions for legitimate admin endpoints. "
                "Review blocked requests to refine patterns."
            ),
            detection_coverage="80% - Blocks common web shell patterns",
            evasion_considerations=(
                "Encoded or novel patterns may bypass WAF. "
                "Combine with EC2 instance monitoring for defence in depth."
            ),
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5/million requests + $5/Web ACL",
            prerequisites=[
                "AWS WAF-compatible resource (ALB, CloudFront, API Gateway)",
                "CloudWatch enabled",
            ],
        ),
        # =====================================================================
        # STRATEGY 4: GCP Cloud Armor + Logging
        # =====================================================================
        DetectionStrategy(
            strategy_id="t1505003-gcp-armor",
            name="GCP Cloud Armor Web Shell Detection",
            description=(
                "Use GCP Cloud Armor security policies to detect and block "
                "web shell patterns at the edge."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_armor",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="http_load_balancer"
jsonPayload.enforcedSecurityPolicy.outcome="DENY"
jsonPayload.enforcedSecurityPolicy.name="webshell-protection"
timestamp>="2024-01-01T00:00:00Z" """,
                gcp_terraform_template="""# GCP Cloud Armor Web Shell Detection
# MITRE ATT&CK: T1505.003

variable "project_id" {
  type        = string
  description = "GCP Project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Cloud Armor security policy
resource "google_compute_security_policy" "webshell_protection" {
  name        = "webshell-protection"
  project     = var.project_id
  description = "Block web shell patterns"

  # Default allow rule
  rule {
    action   = "allow"
    priority = "2147483647"
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
    description = "Default allow"
  }

  # Block web shell URL patterns
  rule {
    action   = "deny(403)"
    priority = "1000"
    match {
      expr {
        expression = <<-EXPR
          request.path.lower().contains('shell') ||
          request.path.lower().contains('backdoor') ||
          request.path.lower().contains('c99') ||
          request.path.lower().contains('r57') ||
          request.query.lower().contains('cmd=') ||
          request.query.lower().contains('command=') ||
          request.query.lower().contains('exec=')
        EXPR
      }
    }
    description = "Block web shell patterns"
  }

  # Block suspicious file extensions with query parameters
  rule {
    action   = "deny(403)"
    priority = "1001"
    match {
      expr {
        expression = <<-EXPR
          (request.path.lower().endsWith('.php') ||
           request.path.lower().endsWith('.asp') ||
           request.path.lower().endsWith('.aspx') ||
           request.path.lower().endsWith('.jsp')) &&
          (request.query.lower().contains('cmd') ||
           request.query.lower().contains('exec') ||
           request.query.lower().contains('shell'))
        EXPR
      }
    }
    description = "Block script files with suspicious parameters"
  }

  # Enable Adaptive Protection
  adaptive_protection_config {
    layer_7_ddos_defense_config {
      enable = true
    }
  }
}

# Notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Web Shell Alerts"
  type         = "email"
  project      = var.project_id

  labels = {
    email_address = var.alert_email
  }
}

# Log-based metric for blocked requests
resource "google_logging_metric" "webshell_blocked" {
  name    = "webshell-blocked-requests"
  project = var.project_id

  filter = <<-EOT
    resource.type="http_load_balancer"
    jsonPayload.enforcedSecurityPolicy.outcome="DENY"
    jsonPayload.enforcedSecurityPolicy.name="webshell-protection"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
  }
}

# Alert policy for blocked requests
resource "google_monitoring_alert_policy" "webshell_alert" {
  project      = var.project_id
  display_name = "Web Shell Pattern Blocked"
  combiner     = "OR"

  conditions {
    display_name = "Cloud Armor blocked web shell pattern"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.webshell_blocked.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 5

      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_COUNT"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  documentation {
    content   = "Cloud Armor blocked potential web shell requests."
    mime_type = "text/markdown"
  }
}

output "security_policy_id" {
  value       = google_compute_security_policy.webshell_protection.id
  description = "Cloud Armor security policy ID"
}""",
                alert_severity="critical",
                alert_title="GCP: Cloud Armor Blocked Web Shell Pattern",
                alert_description_template=(
                    "Cloud Armor blocked potential web shell request."
                ),
                investigation_steps=[
                    "Review Cloud Logging for blocked request details",
                    "Identify source IP and request pattern",
                    "Check if legitimate traffic was blocked",
                    "Scan backend instances for web shells",
                    "Review recent application deployments",
                ],
                containment_actions=[
                    "Block source IP in Cloud Armor",
                    "Scan Compute Engine instances for malware",
                    "Review and rotate service account keys",
                    "Enable VPC Service Controls",
                    "Engage incident response",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning=(
                "Refine CEL expressions to reduce false positives. "
                "Allowlist specific paths if needed."
            ),
            detection_coverage="80% - Edge-level pattern detection",
            evasion_considerations=(
                "Encoded patterns may bypass. " "Combine with backend monitoring."
            ),
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-20/month",
            prerequisites=[
                "GCP Load Balancer",
                "Cloud Armor enabled",
            ],
        ),
    ],
    recommended_order=[
        "t1505003-azure-defender",
        "t1505003-azure-appservice",
        "t1505003-aws-waf",
        "t1505003-gcp-armor",
    ],
    total_effort_hours=6.0,
    coverage_improvement="+20% improvement for Persistence tactic with web shell detection",
)
