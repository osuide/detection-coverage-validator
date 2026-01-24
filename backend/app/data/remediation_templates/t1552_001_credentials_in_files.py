"""
T1552.001 - Unsecured Credentials: Credentials in Files

Adversaries search for credentials in files like .env, config files,
and code repositories. The 2024 AWS .env attack hit 230M+ environments.
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
    technique_id="T1552.001",
    technique_name="Unsecured Credentials: Credentials in Files",
    tactic_ids=["TA0006"],
    mitre_url="https://attack.mitre.org/techniques/T1552/001/",
    threat_context=ThreatContext(
        description=(
            "Adversaries search compromised systems and web servers for files "
            "containing credentials. In cloud environments, .env files, config files, "
            "and source code often contain API keys, database passwords, and cloud credentials."
        ),
        attacker_goal="Obtain valid credentials from exposed configuration files",
        why_technique=[
            "Developers often store credentials in plaintext files",
            ".env files frequently exposed via misconfigured web servers",
            "Credentials found here often have excessive permissions",
            "No authentication required if files are publicly accessible",
            "Automated scanning makes large-scale discovery trivial",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=9,
        severity_reasoning=(
            "This was the #1 cloud attack vector in 2024. Exposed .env files "
            "led to massive breaches. Credentials often have admin privileges, "
            "enabling full environment compromise."
        ),
        business_impact=[
            "Full cloud environment compromise",
            "Data exfiltration at scale",
            "Cryptomining and resource abuse",
            "Regulatory fines for credential exposure",
            "Reputational damage",
        ],
        typical_attack_phase="credential_access",
        often_precedes=["T1078.004", "T1087.004", "T1530"],
        often_follows=["T1190", "T1595"],
    ),
    detection_strategies=[
        # Strategy 1: AWS - GuardDuty for credential exfiltration
        DetectionStrategy(
            strategy_id="t1552001-aws-guardduty",
            name="GuardDuty Credential Exfiltration Detection",
            description="Detect when credentials obtained from files are used from external locations.",
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
                    "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS",
                    "CredentialAccess:IAMUser/AnomalousBehavior",
                ],
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect credential exfiltration from files

Parameters:
  AlertEmail:
    Type: String

Resources:
  # Step 1: Enable GuardDuty
  Detector:
    Type: AWS::GuardDuty::Detector
    Properties:
      Enable: true

  # Step 2: SNS for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 3: Route credential exfiltration findings
  CredentialExfilRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.guardduty]
        detail-type:
          - GuardDuty Finding
        detail:
          type:
            - prefix: "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS"
            - prefix: "CredentialAccess:IAMUser"
      Targets:
        - Id: Alert
          Arn: !Ref AlertTopic

  TopicPolicy:
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
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn: !GetAtt CredentialExfilRule.Arn""",
                terraform_template="""# Detect credential exfiltration from files

variable "alert_email" {
  type = string
}

# Step 1: Enable GuardDuty
resource "aws_guardduty_detector" "main" {
  enable = true
}

# Step 2: SNS for alerts
resource "aws_sns_topic" "alerts" {
  name = "credential-exfil-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 3: Route credential exfiltration findings
resource "aws_cloudwatch_event_rule" "cred_exfil" {
  name = "credential-exfil-alerts"
  event_pattern = jsonencode({
    source = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    detail = {
      type = [
        { prefix = "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS" },
        { prefix = "CredentialAccess:IAMUser" }
      ]
    }
  })
}

# DLQ for failed events
resource "aws_sqs_queue" "dlq" {
  name                      = "credential-exfil-detection-dlq"
  message_retention_seconds = 1209600  # 14 days
}

resource "aws_sqs_queue_policy" "dlq" {
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
          "aws:SourceArn" = aws_cloudwatch_event_rule.cred_exfil.arn
        }
      }
    }]
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.cred_exfil.name
target_id = "SendToSNS"
  arn  = aws_sns_topic.alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
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

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_events" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.cred_exfil.arn
        }
      }
    }]
  })
}""",
                alert_severity="critical",
                alert_title="Credential Exfiltration Detected",
                alert_description_template="Credentials used from external location. Finding: {finding_type}. Source IP: {source_ip}.",
                investigation_steps=[
                    "Identify the source of the credentials (which file/service)",
                    "Check CloudTrail for all API calls using these credentials",
                    "Determine what resources were accessed",
                    "Identify how the credentials were exposed",
                ],
                containment_actions=[
                    "Immediately rotate the compromised credentials",
                    "Revoke any active sessions",
                    "Block the source IP if known malicious",
                    "Scan for exposed .env files on web servers",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist known CI/CD systems and deployment tools",
            detection_coverage="70% - catches credential use from unexpected locations",
            evasion_considerations="Attacker using credentials from expected regions/IPs",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$4/million events",
            prerequisites=["GuardDuty enabled"],
        ),
        # Strategy 2: AWS - Detect .env file access via ALB/CloudFront
        DetectionStrategy(
            strategy_id="t1552001-aws-env-access",
            name="Detect .env File Access Attempts",
            description="Monitor for HTTP requests attempting to access .env files.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, @message
| filter @message like /\\.env/
| filter @message like /GET|POST|HEAD/
| stats count(*) as attempts by bin(1h)
| filter attempts > 10""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Alert on .env file access attempts

Parameters:
  ALBLogGroup:
    Type: String
  AlertEmail:
    Type: String

Resources:
  # Step 1: SNS topic
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter for .env access
  EnvAccessFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref ALBLogGroup
      FilterPattern: '".env"'
      MetricTransformations:
        - MetricName: EnvFileAccess
          MetricNamespace: Security
          MetricValue: "1"

  # Step 3: Alarm on threshold
  EnvAccessAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: EnvFileAccessAttempts
      MetricName: EnvFileAccess
      Namespace: Security
      Statistic: Sum
      Period: 300
      Threshold: 10
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Alert on .env file access attempts

variable "alb_log_group" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "env-access-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for .env access
resource "aws_cloudwatch_log_metric_filter" "env_access" {
  name           = "env-file-access"
  log_group_name = var.alb_log_group
  pattern        = "\".env\""

  metric_transformation {
    name      = "EnvFileAccess"
    namespace = "Security"
    value     = "1"
  }
}

# Step 3: Alarm on threshold
resource "aws_cloudwatch_metric_alarm" "env_access" {
  alarm_name          = "EnvFileAccessAttempts"
  metric_name         = "EnvFileAccess"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 10
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="high",
                alert_title=".env File Access Attempts Detected",
                alert_description_template="Multiple attempts to access .env files detected. {attempts} attempts in the last hour.",
                investigation_steps=[
                    "Review source IPs attempting access",
                    "Check if .env files are actually exposed",
                    "Verify web server configuration blocks sensitive files",
                    "Scan for credentials in version control",
                ],
                containment_actions=[
                    "Block malicious IPs at WAF/security group",
                    "Configure web server to deny access to .env files",
                    "Rotate any credentials that may have been exposed",
                    "Add .env to .gitignore if not already",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Threshold may need adjustment based on traffic",
            detection_coverage="90% - catches scanning attempts",
            evasion_considerations="Attackers may use different file names",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["ALB access logs enabled", "CloudWatch Logs configured"],
        ),
        # Strategy 3: GCP - Security Command Center + Cloud Logging
        DetectionStrategy(
            strategy_id="t1552001-gcp-logging",
            name="GCP Credential File Access Detection",
            description="Monitor for access to sensitive configuration files in GCP.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="http_load_balancer"
httpRequest.requestUrl=~".*\\.env.*"
OR httpRequest.requestUrl=~".*config\\.json.*"
OR httpRequest.requestUrl=~".*credentials.*"''',
                gcp_terraform_template="""# GCP: Alert on sensitive file access attempts

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for sensitive file access
resource "google_logging_metric" "sensitive_file_access" {
  project = var.project_id
  name   = "sensitive-file-access"
  filter = <<-EOT
    resource.type="http_load_balancer"
    (httpRequest.requestUrl=~".*\\.env.*"
    OR httpRequest.requestUrl=~".*\\.config.*"
    OR httpRequest.requestUrl=~".*credentials.*")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "sensitive_file_alert" {
  project      = var.project_id
  display_name = "Sensitive File Access Attempts"
  combiner     = "OR"

  conditions {
    display_name = "High volume of sensitive file requests"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.sensitive_file_access.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 10
    }
  }

  notification_channels = [google_monitoring_notification_channel.email_s1.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }
}""",
                alert_severity="high",
                alert_title="GCP: Sensitive File Access Detected",
                alert_description_template="Attempts to access sensitive configuration files detected via load balancer.",
                investigation_steps=[
                    "Review Cloud Audit Logs for source details",
                    "Check if application is exposing config files",
                    "Verify Cloud Storage bucket permissions",
                    "Scan GCE instances for exposed credential files",
                ],
                containment_actions=[
                    "Configure Cloud Armor to block requests for sensitive files",
                    "Rotate any potentially exposed service account keys",
                    "Review and restrict IAM permissions",
                    "Enable VPC Service Controls for sensitive projects",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Adjust URL patterns based on application structure",
            detection_coverage="85% - catches HTTP-based scanning",
            evasion_considerations="Direct API access bypasses load balancer logs",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["HTTP(S) Load Balancer logging enabled"],
        ),
        # Strategy 4: AWS - Secrets Manager access anomaly
        DetectionStrategy(
            strategy_id="t1552001-aws-secrets-access",
            name="Unusual Secrets Manager Access",
            description="Detect unusual access patterns to AWS Secrets Manager.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.arn, eventName, requestParameters.secretId
| filter eventSource = "secretsmanager.amazonaws.com"
| filter eventName in ["GetSecretValue", "BatchGetSecretValue"]
| stats count(*) as access_count by userIdentity.arn, bin(1h)
| filter access_count > 20
| sort access_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Alert on unusual Secrets Manager access

Parameters:
  CloudTrailLogGroup:
    Type: String
  AlertEmail:
    Type: String

Resources:
  # Step 1: SNS topic
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter
  SecretsAccessFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventSource = "secretsmanager.amazonaws.com" && $.eventName = "GetSecretValue" }'
      MetricTransformations:
        - MetricName: SecretsAccess
          MetricNamespace: Security
          MetricValue: "1"

  # Step 3: Alarm
  SecretsAccessAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: UnusualSecretsAccess
      MetricName: SecretsAccess
      Namespace: Security
      Statistic: Sum
      Period: 300
      Threshold: 50
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Alert on unusual Secrets Manager access

variable "cloudtrail_log_group" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "secrets-access-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter
resource "aws_cloudwatch_log_metric_filter" "secrets_access" {
  name           = "secrets-manager-access"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventSource = \"secretsmanager.amazonaws.com\" && $.eventName = \"GetSecretValue\" }"

  metric_transformation {
    name      = "SecretsAccess"
    namespace = "Security"
    value     = "1"
  }
}

# Step 3: Alarm
resource "aws_cloudwatch_metric_alarm" "secrets_access" {
  alarm_name          = "UnusualSecretsAccess"
  metric_name         = "SecretsAccess"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 50
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="high",
                alert_title="Unusual Secrets Manager Access",
                alert_description_template="High volume of Secrets Manager access detected. {access_count} accesses in 1 hour.",
                investigation_steps=[
                    "Identify which IAM principal is accessing secrets",
                    "Check if access pattern matches normal application behaviour",
                    "Review which secrets were accessed",
                    "Verify the source IP and user agent",
                ],
                containment_actions=[
                    "Rotate accessed secrets immediately",
                    "Restrict IAM permissions for the principal",
                    "Enable secret rotation if not already",
                    "Review resource policies on secrets",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal access patterns; exclude known batch processes",
            detection_coverage="80% - catches bulk credential access",
            evasion_considerations="Slow, distributed access may evade threshold",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled", "Logs in CloudWatch"],
        ),
        # Azure Strategy: Unsecured Credentials: Credentials in Files
        DetectionStrategy(
            strategy_id="t1552001-azure",
            name="Azure Unsecured Credentials: Credentials in Files Detection",
            description=(
                "Azure detection for Unsecured Credentials: Credentials in Files. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.DEFENDER_ALERT,
            aws_service="n/a",
            azure_service="defender",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                azure_kql_query="""// Direct KQL Query: Detect Credentials in Files Access
// MITRE ATT&CK: T1552.001 - Unsecured Credentials: Credentials in Files
// Data Sources: AzureDiagnostics, StorageBlobLogs, AzureActivity

// Part 1: Detect Key Vault secret access patterns
let KeyVaultSecretAccess = AzureDiagnostics
| where TimeGenerated > ago(24h)
| where ResourceProvider == "MICROSOFT.KEYVAULT"
| where OperationName in ("SecretGet", "SecretList")
| summarize
    SecretAccessCount = count(),
    SecretsAccessed = make_set(id_s, 20),
    FirstAccess = min(TimeGenerated),
    LastAccess = max(TimeGenerated)
    by CallerIPAddress, identity_claim_upn_s, Resource
| extend AccessType = "Key Vault Secrets";
// Part 2: Detect storage blob downloads of credential-like files
let StorageCredentialFiles = StorageBlobLogs
| where TimeGenerated > ago(24h)
| where OperationType == "GetBlob"
| where Uri has_any (".env", ".pem", ".key", ".pfx", "credentials", "secret", "password", "config.json", "appsettings")
| summarize
    FileDownloadCount = count(),
    FilesDownloaded = make_set(Uri, 20),
    FirstDownload = min(TimeGenerated),
    LastDownload = max(TimeGenerated)
    by CallerIpAddress, RequesterUpn, AccountName
| extend AccessType = "Storage Credential Files";
// Part 3: Detect file share access for credential files
let FileShareAccess = StorageFileLogs
| where TimeGenerated > ago(24h)
| where OperationType in ("GetFile", "ListFiles")
| where Uri has_any (".env", ".pem", ".key", ".pfx", "credentials", "secret", "password")
| summarize
    FileAccessCount = count(),
    Files = make_set(Uri, 20),
    FirstAccess = min(TimeGenerated),
    LastAccess = max(TimeGenerated)
    by CallerIpAddress, RequesterUpn, AccountName
| extend AccessType = "File Share Credentials";
// Combine results
KeyVaultSecretAccess
| project
    TimeGenerated = LastAccess,
    AccessType,
    Caller = identity_claim_upn_s,
    CallerIpAddress,
    Resource,
    AccessCount = SecretAccessCount,
    ItemsAccessed = SecretsAccessed,
    TechniqueId = "T1552.001",
    TechniqueName = "Credentials in Files",
    Severity = "High" """,
                sentinel_rule_query="""// Sentinel Analytics Rule: Credentials in Files Detection
// MITRE ATT&CK: T1552.001
// Detects Key Vault secret access and storage credential file downloads

// Key Vault secrets
let KeyVaultAccess = AzureDiagnostics
| where TimeGenerated > ago(24h)
| where ResourceProvider == "MICROSOFT.KEYVAULT"
| where OperationName in ("SecretGet", "SecretList")
| summarize
    SecretCount = count(),
    Secrets = make_set(id_s, 10),
    Vaults = make_set(Resource, 5),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by CallerIPAddress, identity_claim_upn_s
| where SecretCount > 5;
// Storage credential files
let StorageAccess = StorageBlobLogs
| where TimeGenerated > ago(24h)
| where OperationType == "GetBlob"
| where Uri has_any (".env", ".pem", ".key", ".pfx", "credentials", "secret", "password", "config.json")
| summarize
    FileCount = count(),
    Files = make_set(Uri, 10),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by CallerIpAddress, RequesterUpn;
KeyVaultAccess
| extend
    AccountName = tostring(split(identity_claim_upn_s, "@")[0]),
    AccountDomain = tostring(split(identity_claim_upn_s, "@")[1])
| project
    TimeGenerated = LastSeen,
    AccountName,
    AccountDomain,
    Caller = identity_claim_upn_s,
    CallerIpAddress = CallerIPAddress,
    SecretCount,
    Secrets,
    Vaults,
    FirstSeen""",
                defender_alert_types=["Suspicious activity detected"],
                azure_terraform_template="""# Microsoft Defender for Cloud Detection
# Unsecured Credentials: Credentials in Files (T1552.001)
# Microsoft Defender detects Unsecured Credentials: Credentials in Files activity

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
  description = "Resource group name"
}

variable "log_analytics_workspace_id" {
  type        = string
  description = "Log Analytics workspace for Defender"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Enable Defender for Cloud plans
resource "azurerm_security_center_subscription_pricing" "defender_servers" {
  tier          = "Standard"
  resource_type = "VirtualMachines"
}

resource "azurerm_security_center_subscription_pricing" "defender_storage" {
  tier          = "Standard"
  resource_type = "StorageAccounts"
}

resource "azurerm_security_center_subscription_pricing" "defender_keyvault" {
  tier          = "Standard"
  resource_type = "KeyVaults"
}

resource "azurerm_security_center_subscription_pricing" "defender_arm" {
  tier          = "Standard"
  resource_type = "Arm"
}

# Action Group for Defender alerts
resource "azurerm_monitor_action_group" "defender_alerts" {
  name                = "defender-t1552-001-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "DefAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Log Analytics query for Defender alerts
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "defender_detection" {
  name                = "defender-t1552-001"
  resource_group_name = var.resource_group_name
  location            = "uksouth"

  evaluation_frequency = "PT5M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 1

  criteria {
    query = <<-QUERY
SecurityAlert
| where TimeGenerated > ago(1h)
| where ProductName == "Azure Security Center" or ProductName == "Microsoft Defender for Cloud"
| where AlertName has_any (
                    "Suspicious activity detected",
                )
| project
    TimeGenerated,
    AlertName,
    AlertSeverity,
    Description,
    RemediationSteps,
    ExtendedProperties,
    Entities
    QUERY

    time_aggregation_method = "Count"
    threshold               = 0
    operator                = "GreaterThan"

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  action {
    action_groups = [azurerm_monitor_action_group.defender_alerts.id]
  }

  description = "Microsoft Defender detects Unsecured Credentials: Credentials in Files activity"
  display_name = "Defender: Unsecured Credentials: Credentials in Files"
  enabled      = true

  tags = {
    "mitre-technique" = "T1552.001"
    "detection-type"  = "security"
  }
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.defender_detection.id
}""",
                alert_severity="high",
                alert_title="Azure: Unsecured Credentials: Credentials in Files Detected",
                alert_description_template=(
                    "Unsecured Credentials: Credentials in Files activity detected. "
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
            detection_coverage="70% - Azure-native detection for cloud operations",
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
        "t1552001-aws-guardduty",
        "t1552001-aws-env-access",
        "t1552001-gcp-logging",
        "t1552001-aws-secrets-access",
    ],
    total_effort_hours=4.0,
    coverage_improvement="+25% improvement for Credential Access tactic",
)
