"""
T1552.004 - Unsecured Credentials: Private Keys

Adversaries search for private cryptographic keys that may be stored insecurely.
Private keys enable authentication, code signing, and encryption without passwords.
In cloud environments, SSH keys, TLS certificates, and service account keys are
prime targets for credential theft.
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
    technique_id="T1552.004",
    technique_name="Unsecured Credentials: Private Keys",
    tactic_ids=["TA0006"],
    mitre_url="https://attack.mitre.org/techniques/T1552/004/",
    threat_context=ThreatContext(
        description=(
            "Adversaries search for private keys stored insecurely on compromised systems. "
            "Private keys enable authentication without passwords and may grant access to "
            "production systems, code signing, TLS termination, and cloud resources. "
            "In Azure, this includes SSH keys in VMs, Key Vault secrets, and service principal credentials."
        ),
        attacker_goal="Obtain private keys for persistent access and lateral movement",
        why_technique=[
            "Private keys often grant privileged access",
            "Keys may be stored without encryption",
            "SSH keys enable VM access",
            "Service principal keys provide API access",
            "Certificate private keys enable impersonation",
        ],
        known_threat_actors=["APT29", "Lazarus Group", "FIN7"],
        recent_campaigns=[],
        prevalence="common",
        trend="stable",
        severity_score=8,
        severity_reasoning=(
            "Private keys provide persistent, password-less access to systems. "
            "Compromised keys enable lateral movement and may go undetected for extended periods."
        ),
        business_impact=[
            "Unauthorised system access",
            "Data exfiltration",
            "Lateral movement across infrastructure",
            "Code signing abuse",
            "TLS interception",
        ],
        typical_attack_phase="credential-access",
        often_precedes=["T1021.004", "T1078.004", "T1570"],
        often_follows=["T1083", "T1005"],
    ),
    detection_strategies=[
        # =====================================================================
        # STRATEGY 1: Azure Key Vault Secret Access Monitoring
        # =====================================================================
        DetectionStrategy(
            strategy_id="t1552004-azure-keyvault",
            name="Azure Key Vault Private Key Access Detection",
            description=(
                "Monitor Azure Key Vault for suspicious access to private keys, "
                "certificates, and secrets. Detect bulk enumeration, unusual access "
                "patterns, and access from unexpected identities."
            ),
            detection_type=DetectionType.SENTINEL_RULE,
            aws_service="n/a",
            azure_service="sentinel",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                azure_kql_query="""// Azure Key Vault Private Key Access Detection
// MITRE ATT&CK: T1552.004 - Private Keys
// Detects suspicious access to keys, certificates, and secrets

let lookback = 1h;
let threshold = 10;

// Monitor Key Vault data plane operations
AzureDiagnostics
| where TimeGenerated > ago(lookback)
| where ResourceProvider == "MICROSOFT.KEYVAULT"
| where Category == "AuditEvent"
| where OperationName in (
    "SecretGet", "SecretList", "SecretBackup",
    "KeyGet", "KeyList", "KeyBackup", "KeyExport",
    "CertificateGet", "CertificateList", "CertificateBackup",
    "CertificateExport"
)
| extend
    CallerIP = CallerIPAddress,
    Caller = identity_claim_upn_s,
    ObjectName = id_s,
    ResultStatus = ResultType
| summarize
    OperationCount = count(),
    UniqueSecrets = dcount(ObjectName),
    Operations = make_set(OperationName, 10),
    Secrets = make_set(ObjectName, 20),
    FirstAccess = min(TimeGenerated),
    LastAccess = max(TimeGenerated)
    by ResourceId, Caller, CallerIP
| where OperationCount > threshold or UniqueSecrets > 5
| project
    TimeGenerated = LastAccess,
    ResourceId,
    Caller,
    CallerIP,
    OperationCount,
    UniqueSecrets,
    Operations,
    Secrets,
    FirstAccess""",
                sentinel_rule_query="""// Sentinel: Key Vault Bulk Secret Access
// MITRE ATT&CK: T1552.004
let lookback = 24h;
let bulkThreshold = 20;

// Detect bulk enumeration of secrets
AzureDiagnostics
| where TimeGenerated > ago(lookback)
| where ResourceProvider == "MICROSOFT.KEYVAULT"
| where OperationName in ("SecretList", "KeyList", "CertificateList")
| extend
    Caller = coalesce(identity_claim_upn_s, identity_claim_oid_s),
    CallerIP = CallerIPAddress
| summarize
    ListOperations = count(),
    VaultsAccessed = dcount(ResourceId),
    Vaults = make_set(ResourceId, 10),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by Caller, CallerIP
| where ListOperations > bulkThreshold or VaultsAccessed > 3
| project
    TimeGenerated = LastSeen,
    Caller,
    CallerIP,
    ListOperations,
    VaultsAccessed,
    Vaults,
    FirstSeen

// Detect first-time access to Key Vault
| union (
    AzureDiagnostics
    | where TimeGenerated > ago(lookback)
    | where ResourceProvider == "MICROSOFT.KEYVAULT"
    | where OperationName startswith "Secret" or OperationName startswith "Key"
    | extend Caller = coalesce(identity_claim_upn_s, identity_claim_oid_s)
    | summarize FirstAccess = min(TimeGenerated) by Caller, ResourceId
    | where FirstAccess > ago(1h)
    | project
        TimeGenerated = FirstAccess,
        Caller,
        CallerIP = "N/A",
        ListOperations = 0,
        VaultsAccessed = 1,
        Vaults = dynamic([]),
        FirstSeen = FirstAccess,
        AlertType = "First Time Access"
)""",
                azure_terraform_template="""# Azure Key Vault Private Key Access Detection
# MITRE ATT&CK: T1552.004

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

# Action Group for Key Vault alerts
resource "azurerm_monitor_action_group" "keyvault_alerts" {
  name                = "keyvault-credential-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "KVCreds"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Bulk secret access detection
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "bulk_access" {
  name                = "keyvault-bulk-secret-access"
  resource_group_name = var.resource_group_name
  location            = "uksouth"

  evaluation_frequency = "PT10M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 2

  criteria {
    query = <<-QUERY
AzureDiagnostics
| where TimeGenerated > ago(1h)
| where ResourceProvider == "MICROSOFT.KEYVAULT"
| where OperationName in ("SecretGet", "SecretList", "KeyGet", "KeyList")
| extend Caller = coalesce(identity_claim_upn_s, identity_claim_oid_s)
| summarize
    OperationCount = count(),
    UniqueItems = dcount(id_s)
    by ResourceId, Caller, CallerIPAddress
| where OperationCount > 20 or UniqueItems > 10
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
    action_groups = [azurerm_monitor_action_group.keyvault_alerts.id]
  }

  description  = "Detects bulk access to Key Vault secrets indicating credential theft"
  display_name = "Key Vault Bulk Secret Access"
  enabled      = true

  tags = {
    "mitre-technique" = "T1552.004"
    "detection-type"  = "credential-access"
  }
}

# Secret export/backup detection
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "secret_export" {
  name                = "keyvault-secret-export"
  resource_group_name = var.resource_group_name
  location            = "uksouth"

  evaluation_frequency = "PT5M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 1

  criteria {
    query = <<-QUERY
AzureDiagnostics
| where TimeGenerated > ago(1h)
| where ResourceProvider == "MICROSOFT.KEYVAULT"
| where OperationName in ("SecretBackup", "KeyBackup", "KeyExport", "CertificateBackup")
| extend Caller = coalesce(identity_claim_upn_s, identity_claim_oid_s)
| project
    TimeGenerated,
    ResourceId,
    OperationName,
    Caller,
    CallerIPAddress,
    ResultType
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
    action_groups = [azurerm_monitor_action_group.keyvault_alerts.id]
  }

  description  = "Detects Key Vault secret backup/export operations"
  display_name = "Key Vault Secret Export Detected"
  enabled      = true

  tags = {
    "mitre-technique" = "T1552.004"
    "severity"        = "critical"
  }
}

output "bulk_access_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.bulk_access.id
}

output "export_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.secret_export.id
}""",
                alert_severity="high",
                alert_title="Azure: Suspicious Key Vault Secret Access",
                alert_description_template=(
                    "Suspicious Key Vault access detected. Caller: {Caller}. "
                    "Operations: {OperationCount}. Unique secrets accessed: {UniqueSecrets}."
                ),
                investigation_steps=[
                    "Review Key Vault diagnostic logs for full operation details",
                    "Verify the caller identity is authorised",
                    "Check if access is from expected IP addresses",
                    "Review the specific secrets/keys accessed",
                    "Check for related activities from the same identity",
                    "Determine if this is part of normal operations or compromise",
                ],
                containment_actions=[
                    "Revoke the caller's access to Key Vault",
                    "Rotate all accessed secrets immediately",
                    "Regenerate any accessed keys or certificates",
                    "Review and restrict Key Vault access policies",
                    "Enable soft-delete and purge protection",
                    "Audit all Key Vault RBAC assignments",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "Baseline normal access patterns per identity. "
                "Allowlist known automation accounts. "
                "Adjust thresholds based on environment."
            ),
            detection_coverage="85% - Comprehensive Key Vault monitoring",
            evasion_considerations=(
                "Attackers may use legitimate credentials from expected locations. "
                "Slow enumeration may evade thresholds."
            ),
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$15-40 (Log Analytics)",
            prerequisites=[
                "Azure Key Vault with diagnostic logging enabled",
                "Log Analytics workspace",
                "AuditEvent logs collected",
            ],
        ),
        # =====================================================================
        # STRATEGY 2: Azure VM SSH Key Access Detection
        # =====================================================================
        DetectionStrategy(
            strategy_id="t1552004-azure-ssh",
            name="Azure VM SSH Key Access Detection",
            description=(
                "Monitor Azure VMs for access to SSH private keys and related files. "
                "Uses Azure Defender for Servers and Syslog to detect key file access."
            ),
            detection_type=DetectionType.SENTINEL_RULE,
            aws_service="n/a",
            azure_service="sentinel",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                azure_kql_query="""// Azure VM SSH Key Access Detection
// MITRE ATT&CK: T1552.004 - Private Keys
// Detects access to SSH private key files on Linux VMs

let lookback = 1h;

// Monitor file access to SSH key locations
Syslog
| where TimeGenerated > ago(lookback)
| where Facility == "auth" or Facility == "authpriv"
| where SyslogMessage has_any (".ssh/", "id_rsa", "id_ecdsa", "id_ed25519", ".pem")
| extend
    KeyFile = extract(@"([\w/]+\.ssh/[\w.-]+|[\w/]+\.pem|[\w/]+id_\w+)", 0, SyslogMessage),
    User = extract(@"user[= ](\w+)", 1, SyslogMessage),
    Process = extract(@"(\w+)\[\d+\]:", 1, SyslogMessage)
| where isnotempty(KeyFile)
| summarize
    AccessCount = count(),
    KeyFiles = make_set(KeyFile, 20),
    Processes = make_set(Process, 10),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by Computer, User
| project
    TimeGenerated = LastSeen,
    Computer,
    User,
    AccessCount,
    KeyFiles,
    Processes,
    FirstSeen""",
                sentinel_rule_query="""// Sentinel: SSH Key File Access
// MITRE ATT&CK: T1552.004
let lookback = 24h;

// Combine auditd and security events for comprehensive coverage
let AuditdKeyAccess = Syslog
| where TimeGenerated > ago(lookback)
| where ProcessName == "auditd" or Facility == "auth"
| where SyslogMessage has_any ("id_rsa", "id_ecdsa", "id_ed25519", ".pem", "authorized_keys")
| where SyslogMessage has_any ("open", "read", "execve", "cat", "cp", "scp")
| extend
    Action = "FileAccess",
    KeyFile = extract(@"([\w/.-]+(?:id_\w+|\.pem|authorized_keys))", 0, SyslogMessage)
| where isnotempty(KeyFile);

// Detect SSH key generation (could be key replacement attack)
let KeyGeneration = Syslog
| where TimeGenerated > ago(lookback)
| where SyslogMessage has "ssh-keygen"
| extend Action = "KeyGeneration";

AuditdKeyAccess
| union KeyGeneration
| summarize
    EventCount = count(),
    Actions = make_set(Action, 10),
    KeyFiles = make_set(KeyFile, 20),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by Computer
| where EventCount > 3
| project
    TimeGenerated = LastSeen,
    Computer,
    EventCount,
    Actions,
    KeyFiles,
    FirstSeen""",
                azure_terraform_template="""# Azure VM SSH Key Access Detection
# MITRE ATT&CK: T1552.004

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

resource "azurerm_monitor_action_group" "ssh_alerts" {
  name                = "ssh-key-access-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "SSHKeys"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

resource "azurerm_monitor_scheduled_query_rules_alert_v2" "ssh_key_access" {
  name                = "vm-ssh-key-access"
  resource_group_name = var.resource_group_name
  location            = "uksouth"

  evaluation_frequency = "PT10M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 2

  criteria {
    query = <<-QUERY
Syslog
| where TimeGenerated > ago(1h)
| where Facility in ("auth", "authpriv")
| where SyslogMessage has_any ("id_rsa", "id_ecdsa", "id_ed25519", ".pem")
| where SyslogMessage has_any ("read", "open", "cat", "cp", "scp")
| extend KeyFile = extract(@"([\w/.-]+(?:id_\w+|\.pem))", 0, SyslogMessage)
| where isnotempty(KeyFile)
| summarize AccessCount = count() by Computer, KeyFile
| where AccessCount > 3
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
    action_groups = [azurerm_monitor_action_group.ssh_alerts.id]
  }

  description  = "Detects access to SSH private key files on VMs"
  display_name = "SSH Private Key Access Detected"
  enabled      = true

  tags = {
    "mitre-technique" = "T1552.004"
  }
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.ssh_key_access.id
}""",
                alert_severity="high",
                alert_title="Azure: SSH Private Key Access Detected",
                alert_description_template=(
                    "SSH private key access detected on {Computer}. "
                    "Key files: {KeyFiles}. Access count: {AccessCount}."
                ),
                investigation_steps=[
                    "Review Syslog for the SSH key access events",
                    "Identify the user and process accessing keys",
                    "Check if this is legitimate admin activity",
                    "Review recent SSH logins to the VM",
                    "Check for data exfiltration from the VM",
                ],
                containment_actions=[
                    "Rotate all SSH keys on the affected VM",
                    "Revoke any authorized_keys entries",
                    "Check for backdoor accounts",
                    "Review NSG rules for the VM",
                    "Enable Azure Defender for Servers if not active",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "Exclude known admin users and automation. "
                "Tune based on legitimate SSH key operations."
            ),
            detection_coverage="70% - Syslog-based detection",
            evasion_considerations=(
                "Attackers may read keys without triggering syslog. "
                "Consider enabling auditd for comprehensive file access monitoring."
            ),
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-30 (Log Analytics)",
            prerequisites=[
                "Azure VMs with Syslog collection enabled",
                "Log Analytics agent or Azure Monitor Agent",
                "Syslog forwarding configured",
            ],
        ),
        # =====================================================================
        # STRATEGY 3: AWS Secrets Manager Access Monitoring
        # =====================================================================
        DetectionStrategy(
            strategy_id="t1552004-aws-secrets",
            name="AWS Secrets Manager Credential Access Detection",
            description=(
                "Monitor AWS Secrets Manager for suspicious access to stored credentials "
                "and private keys. Detect bulk retrieval and unusual access patterns."
            ),
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="secretsmanager",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                terraform_template="""# AWS Secrets Manager Credential Access Detection
# MITRE ATT&CK: T1552.004

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# SNS topic for alerts
resource "aws_sns_topic" "secrets_alerts" {
  name              = "secrets-manager-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.secrets_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# EventBridge rule for secret access
resource "aws_cloudwatch_event_rule" "secrets_access" {
  name        = "secrets-manager-access"
  description = "Monitor Secrets Manager GetSecretValue calls"

  event_pattern = jsonencode({
    source      = ["aws.secretsmanager"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["secretsmanager.amazonaws.com"]
      eventName   = [
        "GetSecretValue",
        "BatchGetSecretValue",
        "ListSecrets",
        "DescribeSecret"
      ]
    }
  })
}

resource "aws_sqs_queue" "secrets_dlq" {
  name                      = "secrets-access-dlq"
  message_retention_seconds = 1209600
}

resource "aws_cloudwatch_event_target" "to_sns" {
  rule      = aws_cloudwatch_event_rule.secrets_access.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.secrets_alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.secrets_dlq.arn
  }

  input_transformer {
    input_paths = {
      principal  = "$.detail.userIdentity.arn"
      eventName  = "$.detail.eventName"
      secretId   = "$.detail.requestParameters.secretId"
      sourceIp   = "$.detail.sourceIPAddress"
      eventTime  = "$.detail.eventTime"
    }
    input_template = <<-EOF
      {
        "alert": "Secrets Manager Access",
        "principal": "<principal>",
        "action": "<eventName>",
        "secret": "<secretId>",
        "sourceIp": "<sourceIp>",
        "time": "<eventTime>"
      }
    EOF
  }
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_events" {
  arn = aws_sns_topic.secrets_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowEventBridge"
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.secrets_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.secrets_access.arn
        }
      }
    }]
  })
}

# CloudWatch metric for bulk access
resource "aws_cloudwatch_log_metric_filter" "bulk_secrets" {
  name           = "bulk-secrets-access"
  log_group_name = "aws-cloudtrail-logs"
  pattern        = "{ $.eventSource = \"secretsmanager.amazonaws.com\" && $.eventName = \"GetSecretValue\" }"

  metric_transformation {
    name      = "SecretsAccess"
    namespace = "Security/SecretsManager"
    value     = "1"
    dimensions = {
      Principal = "$.userIdentity.arn"
    }
  }
}

resource "aws_cloudwatch_metric_alarm" "bulk_access" {
  alarm_name          = "bulk-secrets-access"
  alarm_description   = "Bulk secrets access detected"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "SecretsAccess"
  namespace           = "Security/SecretsManager"
  period              = 300
  statistic           = "Sum"
  threshold           = 20
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.secrets_alerts.arn]
}

output "alert_topic_arn" {
  value = aws_sns_topic.secrets_alerts.arn
}""",
                alert_severity="high",
                alert_title="AWS: Secrets Manager Access Detected",
                alert_description_template=(
                    "Secrets Manager access: {action} by {principal} on {secret}."
                ),
                investigation_steps=[
                    "Review CloudTrail for the secret access event",
                    "Verify the principal is authorised to access the secret",
                    "Check source IP against known locations",
                    "Review the secret's access policy",
                    "Check for related activities from the principal",
                ],
                containment_actions=[
                    "Rotate the accessed secret immediately",
                    "Revoke the principal's access",
                    "Review and restrict secret resource policies",
                    "Enable secret rotation if not configured",
                    "Enable AWS KMS key monitoring",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "Exclude known application service roles. "
                "Baseline normal access patterns per secret."
            ),
            detection_coverage="85% - CloudTrail-based detection",
            evasion_considerations=(
                "Attackers using compromised credentials appear legitimate."
            ),
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-15 (EventBridge + CloudWatch)",
            prerequisites=[
                "CloudTrail enabled",
                "Secrets Manager in use",
            ],
        ),
        # =====================================================================
        # STRATEGY 4: GCP Secret Manager Access Detection
        # =====================================================================
        DetectionStrategy(
            strategy_id="t1552004-gcp-secrets",
            name="GCP Secret Manager Access Detection",
            description=(
                "Monitor GCP Secret Manager for access to stored credentials "
                "and private keys using Cloud Audit Logs."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="secret_manager",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""protoPayload.serviceName="secretmanager.googleapis.com"
protoPayload.methodName=~"AccessSecretVersion|ListSecretVersions|GetSecret"
severity>=NOTICE
timestamp>="2024-01-01T00:00:00Z" """,
                gcp_terraform_template="""# GCP Secret Manager Access Detection
# MITRE ATT&CK: T1552.004

variable "project_id" {
  type        = string
  description = "GCP Project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

resource "google_monitoring_notification_channel" "email" {
  display_name = "Secret Access Alerts"
  type         = "email"
  project      = var.project_id

  labels = {
    email_address = var.alert_email
  }
}

resource "google_logging_metric" "secret_access" {
  name    = "secret-manager-access"
  project = var.project_id

  filter = <<-EOT
    protoPayload.serviceName="secretmanager.googleapis.com"
    protoPayload.methodName=~"AccessSecretVersion|GetSecretValue"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
    labels {
      key         = "principal"
      value_type  = "STRING"
    }
    labels {
      key         = "secret"
      value_type  = "STRING"
    }
  }

  label_extractors = {
    "principal" = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
    "secret"    = "EXTRACT(resource.labels.secret_id)"
  }
}

resource "google_monitoring_alert_policy" "bulk_secret_access" {
  project      = var.project_id
  display_name = "Bulk Secret Manager Access"
  combiner     = "OR"

  conditions {
    display_name = "High volume secret access"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.secret_access.name}\""
      duration        = "60s"
      comparison      = "COMPARISON_GT"
      threshold_value = 20

      aggregations {
        alignment_period     = "60s"
        per_series_aligner   = "ALIGN_COUNT"
        cross_series_reducer = "REDUCE_SUM"
        group_by_fields      = ["metric.label.principal"]
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  documentation {
    content   = "Bulk access to Secret Manager detected."
    mime_type = "text/markdown"
  }
}

resource "google_logging_metric" "secret_list" {
  name    = "secret-manager-list"
  project = var.project_id

  filter = <<-EOT
    protoPayload.serviceName="secretmanager.googleapis.com"
    protoPayload.methodName="ListSecrets"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
  }
}

resource "google_monitoring_alert_policy" "secret_enumeration" {
  project      = var.project_id
  display_name = "Secret Manager Enumeration"
  combiner     = "OR"

  conditions {
    display_name = "Secret listing detected"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.secret_list.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 5

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_COUNT"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  documentation {
    content   = "Secret Manager enumeration activity detected."
    mime_type = "text/markdown"
  }
}

output "alert_policy_id" {
  value = google_monitoring_alert_policy.bulk_secret_access.id
}""",
                alert_severity="high",
                alert_title="GCP: Secret Manager Access Detected",
                alert_description_template=(
                    "Secret Manager access by {principal} to {secret}."
                ),
                investigation_steps=[
                    "Review Cloud Audit Logs for access details",
                    "Verify the principal is authorised",
                    "Check the IAM bindings for the secret",
                    "Review related activities from the principal",
                    "Determine if secrets were exfiltrated",
                ],
                containment_actions=[
                    "Rotate the accessed secrets",
                    "Revoke IAM bindings for the principal",
                    "Add VPC Service Controls",
                    "Enable Secret Manager automatic rotation",
                    "Review organisation policies",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "Baseline normal access per service account. "
                "Exclude known automation identities."
            ),
            detection_coverage="85% - Audit log-based detection",
            evasion_considerations=(
                "Legitimate credentials from expected locations appear normal."
            ),
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-30 (Cloud Logging + Monitoring)",
            prerequisites=[
                "Cloud Audit Logs enabled",
                "Secret Manager in use",
            ],
        ),
    ],
    recommended_order=[
        "t1552004-azure-keyvault",
        "t1552004-azure-ssh",
        "t1552004-aws-secrets",
        "t1552004-gcp-secrets",
    ],
    total_effort_hours=6.0,
    coverage_improvement="+18% improvement for Credential Access tactic with key monitoring",
)
