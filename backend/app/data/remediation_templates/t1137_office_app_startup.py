"""
T1137 - Office Application Startup

Adversaries exploit Microsoft Office applications to establish persistence across system
restarts using template macros, add-ins, and Outlook-specific features. Used by APT32 and
Gamaredon Group for persistent backdoor access.
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
    technique_id="T1137",
    technique_name="Office Application Startup",
    tactic_ids=["TA0003"],
    mitre_url="https://attack.mitre.org/techniques/T1137/",
    threat_context=ThreatContext(
        description=(
            "Adversaries exploit Microsoft Office applications to establish persistence by "
            "leveraging template macros, add-ins, Outlook rules, forms, and homepage settings. "
            "These mechanisms function in both standalone Office installations and Office 365 "
            "environments, allowing malicious code to execute automatically when Office applications "
            "start. This includes VBA macros in templates, COM add-ins, Outlook forms (FORMS\\IPM), "
            "Outlook homepage settings, and the Office Test registry key for persistent script execution."
        ),
        attacker_goal="Establish persistent code execution through Office application startup mechanisms",
        why_technique=[
            "Persists across system reboots and Office application restarts",
            "Legitimate Office features make detection difficult",
            "No administrative privileges required for most methods",
            "Works in both standalone and cloud Office environments",
            "Can execute without triggering traditional malware signatures",
            "Multiple sub-techniques provide redundancy",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="moderate",
        trend="stable",
        severity_score=7,
        severity_reasoning=(
            "Office Application Startup provides reliable persistence with low detection rates. "
            "Particularly effective in enterprise environments with Microsoft Office deployments. "
            "Can be combined with social engineering for initial document compromise."
        ),
        business_impact=[
            "Persistent unauthorised access to endpoints",
            "Data exfiltration via Office application hooks",
            "Credential harvesting through macro execution",
            "Lateral movement using compromised Office features",
            "Compliance violations for endpoint security controls",
        ],
        typical_attack_phase="persistence",
        often_precedes=["T1003", "T1083", "T1057", "T1082"],
        often_follows=["T1566", "T1204", "T1105"],
    ),
    detection_strategies=[
        # Strategy 1: AWS WorkSpaces File Monitoring
        DetectionStrategy(
            strategy_id="t1137-aws-workspaces",
            name="AWS WorkSpaces Office Persistence Monitoring",
            description=(
                "Monitor AWS WorkSpaces instances for Office application persistence mechanisms "
                "by tracking file changes in Office startup directories and registry modifications "
                "through CloudWatch Logs integration."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query=r"""fields @timestamp, @message, instance_id, user_identity
| filter @message like /VbaProject.OTM|STARTUP|\.otm|\.wll|\.xlam|Office.*Test|HKCU.*Office/
| filter @message like /Created|Modified|Registry.*Set/
| parse @message /(?<action>Created|Modified|Set).*(?<path>.*\.(otm|wll|xlam|dotm))/
| stats count(*) as modification_count by instance_id, user_identity, path, bin(1h)
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect Office persistence in AWS WorkSpaces for T1137

Parameters:
  WorkSpacesLogGroup:
    Type: String
    Description: CloudWatch log group for WorkSpaces file monitoring
  AlertEmail:
    Type: String
    Description: Email for Office persistence alerts

Resources:
  # Step 1: Create SNS topic for Office persistence alerts
  OfficePersistenceAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: Office Application Startup Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Create metric filter for Office persistence files
  OfficePersistenceFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref WorkSpacesLogGroup
      FilterPattern: '{ ($.event_data.file_path = "*.otm" || $.event_data.file_path = "*.wll" || $.event_data.file_path = "*.xlam" || $.event_data.file_path = "*STARTUP*") && ($.event_data.action = "Created" || $.event_data.action = "Modified") }'
      MetricTransformations:
        - MetricName: OfficePersistenceActivity
          MetricNamespace: Security/T1137
          MetricValue: "1"

  # Step 3: Create alarm for Office persistence activity
  OfficePersistenceAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1137-OfficeApplicationStartup
      AlarmDescription: Office application persistence mechanism detected in WorkSpaces
      MetricName: OfficePersistenceActivity
      Namespace: Security/T1137
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 0
      ComparisonOperator: GreaterThanThreshold
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref OfficePersistenceAlertTopic""",
                terraform_template="""# AWS WorkSpaces Office Persistence Detection

variable "workspaces_log_group" {
  type        = string
  description = "CloudWatch log group for WorkSpaces file monitoring"
}

variable "alert_email" {
  type        = string
  description = "Email for Office persistence alerts"
}

variable "location" {
  type        = string
  description = "Azure region for resources"
  default     = "uksouth"
}

# Step 1: Create SNS topic for Office persistence alerts
resource "aws_sns_topic" "office_persistence_alerts" {
  name         = "office-application-startup-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "Office Application Startup Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.office_persistence_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for Office persistence files
resource "aws_cloudwatch_log_metric_filter" "office_persistence" {
  name           = "office-persistence-activity"
  log_group_name = var.workspaces_log_group
  pattern        = "{ ($.event_data.file_path = \"*.otm\" || $.event_data.file_path = \"*.wll\" || $.event_data.file_path = \"*.xlam\" || $.event_data.file_path = \"*STARTUP*\") && ($.event_data.action = \"Created\" || $.event_data.action = \"Modified\") }"

  metric_transformation {
    name      = "OfficePersistenceActivity"
    namespace = "Security/T1137"
    value     = "1"
  }
}

# Step 3: Create alarm for Office persistence activity
resource "aws_cloudwatch_metric_alarm" "office_persistence" {
  alarm_name          = "T1137-OfficeApplicationStartup"
  alarm_description   = "Office application persistence mechanism detected in WorkSpaces"
  metric_name         = "OfficePersistenceActivity"
  namespace           = "Security/T1137"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.office_persistence_alerts.arn]
}

# SNS topic policy
data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.office_persistence_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchPublish"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.office_persistence_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="Office Application Startup Persistence Detected",
                alert_description_template=(
                    "Office persistence file {file_path} was {action} on WorkSpace instance {instance_id}. "
                    "This may indicate Office Application Startup technique (T1137)."
                ),
                investigation_steps=[
                    "Identify the WorkSpace instance and user who created/modified the file",
                    "Review the specific file path and type (.otm, .wll, .xlam, .dotm)",
                    "Check for VbaProject.OTM modifications in Outlook startup directory",
                    "Examine registry changes related to HKCU\\Software\\Microsoft\\Office\\<version>\\<app>\\Addins",
                    "Review user's recent email attachments and document downloads",
                    "Check for other Office persistence mechanisms on the same instance",
                ],
                containment_actions=[
                    "Isolate the affected WorkSpace instance from network",
                    "Delete unauthorised Office template and add-in files",
                    "Remove malicious registry keys under Office Test and Addins paths",
                    "Scan the WorkSpace for additional malware and persistence mechanisms",
                    "Reset the WorkSpace to clean snapshot if compromise is confirmed",
                    "Review and block suspicious email attachments organisation-wide",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "Whitelist approved corporate Office templates and add-ins; "
                "focus on modifications outside business hours; baseline normal Office customisation patterns"
            ),
            detection_coverage="75% - catches file-based persistence in monitored WorkSpaces",
            evasion_considerations=(
                "Attackers may use legitimate-looking filenames; "
                "registry-only persistence may not generate file logs; "
                "requires WorkSpaces to have file monitoring agent installed"
            ),
            implementation_effort=EffortLevel.HIGH,
            implementation_time="3-4 hours",
            estimated_monthly_cost="$15-30 depending on WorkSpaces count",
            prerequisites=[
                "AWS WorkSpaces deployed with CloudWatch agent",
                "File integrity monitoring enabled for Office directories",
                "Windows event logs forwarded to CloudWatch Logs",
            ],
        ),
        # Strategy 2: Microsoft 365/Office 365 Macro Execution Monitoring
        DetectionStrategy(
            strategy_id="t1137-m365-macro",
            name="Microsoft 365 Macro Execution Detection",
            description=(
                "Detect suspicious Office macro execution and VBA activity in Microsoft 365 "
                "through Office 365 audit logs and Defender for Office 365 alerts."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query=r"""fields @timestamp, event_source, operation, user_id, workload
| filter event_source = "Office365" or workload = "Exchange" or workload = "OneDrive"
| filter operation in ["FileMalwareDetected", "FileScanned", "VirusScan", "FileModified"]
| filter @message like /macro|vba|\.otm|\.xlam|\.wll|\.dotm/i
| stats count(*) as macro_events by user_id, operation, bin(1h)
| sort @timestamp desc""",
                terraform_template="""# Microsoft 365 Macro Execution Detection (via CloudWatch integration)

variable "office365_log_group" {
  type        = string
  description = "CloudWatch log group receiving Office 365 audit logs"
}

variable "alert_email" {
  type        = string
  description = "Email for macro execution alerts"
}

variable "location" {
  type        = string
  description = "Azure region for resources"
  default     = "uksouth"
}

# Step 1: Create SNS topic for macro execution alerts
resource "aws_sns_topic" "m365_macro_alerts" {
  name         = "m365-macro-execution-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "Microsoft 365 Macro Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.m365_macro_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for Office macro activity
resource "aws_cloudwatch_log_metric_filter" "m365_macro" {
  name           = "m365-macro-execution"
  log_group_name = var.office365_log_group
  pattern        = "{ ($.Workload = \"Exchange\" || $.Workload = \"OneDrive\") && ($.Operation = \"FileMalwareDetected\" || $.Operation = \"FileScanned\") && $.Item.FileExtension IN [\"otm\", \"xlam\", \"wll\", \"dotm\", \"docm\", \"xlsm\"] }"

  metric_transformation {
    name      = "Office365MacroActivity"
    namespace = "Security/T1137"
    value     = "1"
  }
}

# Step 3: Create alarm for suspicious macro activity
resource "aws_cloudwatch_metric_alarm" "m365_macro" {
  alarm_name          = "T1137-M365MacroExecution"
  alarm_description   = "Suspicious Office macro activity detected in Microsoft 365"
  metric_name         = "Office365MacroActivity"
  namespace           = "Security/T1137"
  statistic           = "Sum"
  period              = 600
  evaluation_periods  = 1
  threshold           = 2
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.m365_macro_alerts.arn]
}""",
                alert_severity="high",
                alert_title="Microsoft 365 Suspicious Macro Activity",
                alert_description_template=(
                    "Suspicious Office macro activity detected for user {user_id} in Microsoft 365. "
                    "Operation: {operation}. This may indicate Office Application Startup persistence."
                ),
                investigation_steps=[
                    "Review the specific Office document and file type flagged",
                    "Check user's email for phishing attempts with macro-enabled attachments",
                    "Examine OneDrive/SharePoint for recently uploaded macro files",
                    "Review Defender for Office 365 detections for this user",
                    "Check if user has opened documents from external/untrusted sources",
                    "Investigate if templates were downloaded from suspicious locations",
                ],
                containment_actions=[
                    "Quarantine malicious Office documents in Exchange Online",
                    "Remove macro-enabled files from OneDrive/SharePoint",
                    "Disable macros organisation-wide via Group Policy or Intune",
                    "Block external macro-enabled attachments at email gateway",
                    "Reset user credentials if persistence is confirmed",
                    "Apply Attack Surface Reduction rules to block Office child processes",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "Whitelist approved business macro-enabled templates; "
                "distinguish between malware detections and routine scans; "
                "focus on uncommon file extensions like .otm and .wll"
            ),
            detection_coverage="70% - catches macro activity in cloud Office 365 workloads",
            evasion_considerations=(
                "Locally stored templates on endpoints may not be visible; "
                "attackers may use password-protected macros; "
                "requires Office 365 audit logging enabled"
            ),
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=[
                "Office 365 E3/E5 or Microsoft 365 E3/E5 licensing",
                "Office 365 audit logging enabled and forwarded to CloudWatch",
                "Defender for Office 365 or equivalent protection",
            ],
        ),
        # Strategy 3: GCP Workspace Macro and Add-in Detection
        DetectionStrategy(
            strategy_id="t1137-gcp-workspace",
            name="Google Workspace Office Add-in Detection",
            description=(
                "Monitor Google Workspace for installation of suspicious third-party Office add-ins "
                "and document macro activity that could indicate persistence attempts in cloud-based "
                "Office alternatives."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.serviceName="admin.googleapis.com"
AND (
    protoPayload.methodName=~".*marketplace.*install.*"
    OR protoPayload.methodName=~".*addon.*create.*"
    OR protoPayload.methodName="INSTALL_APPLICATION"
)
AND protoPayload.request.applicationName=~".*Office.*|.*Macro.*|.*Script.*"
severity >= "NOTICE"''',
                gcp_terraform_template="""# GCP: Detect Google Workspace Office add-in installations

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for add-in installation alerts"
}

variable "location" {
  type        = string
  description = "Azure region for resources"
  default     = "uksouth"
}

# Step 1: Create log-based metric for add-in installations
resource "google_logging_metric" "office_addon" {
  project = var.project_id
  name   = "workspace-office-addon-installs"
  filter = <<-EOT
    protoPayload.serviceName="admin.googleapis.com"
    AND (
        protoPayload.methodName=~".*marketplace.*install.*"
        OR protoPayload.methodName=~".*addon.*create.*"
        OR protoPayload.methodName="INSTALL_APPLICATION"
    )
    AND protoPayload.request.applicationName=~".*Office.*|.*Macro.*|.*Script.*"
    severity >= "NOTICE"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "user_email"
      value_type  = "STRING"
      description = "User who installed the add-in"
    }
  }

  label_extractors = {
    "user_email" = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
  }
}

# Step 2: Create notification channel
resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "Office Add-in Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 3: Create alert policy for suspicious add-in installations
resource "google_monitoring_alert_policy" "office_addon" {
  project      = var.project_id
  display_name = "T1137 - Suspicious Office Add-in Installation"
  combiner     = "OR"

  conditions {
    display_name = "Office add-in or macro tool installed"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.office_addon.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }

  notification_channels = [google_monitoring_notification_channel.email_s1.id]

  alert_strategy {
    notification_rate_limit {
      period = "300s"
    }
  }

  documentation {
    content   = "Suspicious Office-related add-in or macro tool was installed in Google Workspace. Investigate for T1137 Office Application Startup persistence."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="medium",
                alert_title="GCP: Suspicious Office Add-in Installation",
                alert_description_template=(
                    "User {user_email} installed Office-related add-in: {application_name}. "
                    "Review for potential Office Application Startup persistence attempt."
                ),
                investigation_steps=[
                    "Identify the specific add-in or application installed",
                    "Review the add-in's permissions and capabilities",
                    "Check if the add-in was approved through organisation's review process",
                    "Investigate user's recent Google Drive activity for suspicious documents",
                    "Review Google Workspace Marketplace permissions granted to the add-in",
                    "Check for similar add-in installations across other users",
                ],
                containment_actions=[
                    "Uninstall unauthorised add-ins from affected user accounts",
                    "Block the add-in organisation-wide via Google Workspace Admin Console",
                    "Review and revoke OAuth permissions granted to suspicious add-ins",
                    "Enable Google Workspace add-on allowlist for the organisation",
                    "Educate users on approved add-in installation procedures",
                    "Implement application allow list in Google Workspace Admin Console",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "Maintain allowlist of approved business productivity add-ins; "
                "focus on add-ins with macro/script capabilities; "
                "correlate with other suspicious user behaviour"
            ),
            detection_coverage="60% - catches add-in installations in Google Workspace",
            evasion_considerations=(
                "Native Google Workspace features differ from traditional Office persistence; "
                "attackers may use legitimate add-ins for malicious purposes; "
                "limited visibility into client-side Office installations"
            ),
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$10-15",
            prerequisites=[
                "Google Workspace Enterprise or Business Plus licensing",
                "Admin audit logging enabled in Google Workspace",
                "Marketplace app installation monitoring enabled",
            ],
        ),
        # Strategy 4: Registry-based Detection for Cloud VDI
        DetectionStrategy(
            strategy_id="t1137-registry-monitoring",
            name="Office Registry Persistence Detection (Cloud VDI)",
            description=(
                "Monitor Windows registry modifications related to Office Test keys and add-in "
                "registration in cloud-hosted virtual desktop environments (AWS WorkSpaces, "
                "Azure Virtual Desktop, GCP Cloud Workstations)."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, registry_path, registry_value, user_identity, instance_id
| filter event_id = 13 or event_name = "RegistryValueSet"
| filter registry_path like /HKCU.*Office.*Test|HKCU.*Office.*Addins|HKCU.*Office.*Options/
| filter registry_path like /Word|Excel|Outlook|PowerPoint/
| stats count(*) as registry_modifications by user_identity, registry_path, bin(1h)
| sort @timestamp desc""",
                terraform_template="""# Office Registry Persistence Detection for Cloud VDI

variable "vdi_log_group" {
  type        = string
  description = "CloudWatch log group for VDI registry monitoring (Sysmon Event ID 13)"
}

variable "alert_email" {
  type        = string
  description = "Email for registry persistence alerts"
}

variable "location" {
  type        = string
  description = "Azure region for resources"
  default     = "uksouth"
}

# Step 1: Create SNS topic for registry alerts
resource "aws_sns_topic" "registry_persistence_alerts" {
  name         = "office-registry-persistence-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "Office Registry Persistence Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.registry_persistence_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for Office registry modifications
resource "aws_cloudwatch_log_metric_filter" "office_registry" {
  name           = "office-registry-persistence"
  log_group_name = var.vdi_log_group
  pattern        = "{ ($.EventID = 13) && ($.TargetObject = \"*Office*Test*\" || $.TargetObject = \"*Office*Addins*\" || $.TargetObject = \"*Office*Options*\") }"

  metric_transformation {
    name      = "OfficeRegistryPersistence"
    namespace = "Security/T1137"
    value     = "1"
  }
}

# Step 3: Create alarm for Office registry persistence
resource "aws_cloudwatch_metric_alarm" "office_registry" {
  alarm_name          = "T1137-OfficeRegistryPersistence"
  alarm_description   = "Office registry persistence mechanism detected in VDI environment"
  metric_name         = "OfficeRegistryPersistence"
  namespace           = "Security/T1137"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.registry_persistence_alerts.arn]
}""",
                alert_severity="high",
                alert_title="Office Registry Persistence Detected",
                alert_description_template=(
                    "Office registry persistence key modified: {registry_path} on instance {instance_id}. "
                    "User: {user_identity}. Potential T1137 Office Application Startup technique."
                ),
                investigation_steps=[
                    "Identify the exact registry path modified (Test, Addins, or Options key)",
                    "Review the registry value data for malicious DLL or script paths",
                    "Check for Office Test key abuse (HKCU\\Software\\Microsoft\\Office\\<version>\\<app>\\Test)",
                    "Examine Addins registry for unauthorised COM add-in registrations",
                    "Correlate with recent process creation or file write events",
                    "Search for additional persistence mechanisms on the same endpoint",
                ],
                containment_actions=[
                    "Delete malicious registry keys under Office Test and Addins paths",
                    "Remove unauthorised DLL or script files referenced in registry values",
                    "Disable affected Office application until remediation is complete",
                    "Deploy Group Policy to block Office Test key usage organisation-wide",
                    "Scan endpoint for additional malware and persistence mechanisms",
                    "Rebuild VDI instance from clean golden image if heavily compromised",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning=(
                "Whitelist legitimate corporate add-in registry paths; "
                "Office Test key usage should be extremely rare and investigated; "
                "baseline expected add-in installations during initial VDI setup"
            ),
            detection_coverage="85% - catches registry-based persistence if Sysmon is deployed",
            evasion_considerations=(
                "Requires Sysmon or equivalent EDR with registry monitoring; "
                "attackers may use alternate persistence locations; "
                "legitimate software may create Office add-ins"
            ),
            implementation_effort=EffortLevel.HIGH,
            implementation_time="4 hours",
            estimated_monthly_cost="$20-40 depending on VDI instance count",
            prerequisites=[
                "Sysmon deployed on VDI instances with registry monitoring (Event ID 13)",
                "Windows event logs forwarded to CloudWatch Logs",
                "CloudWatch agent configured for custom log collection",
            ],
        ),
        # Azure Strategy: Office Application Startup
        DetectionStrategy(
            strategy_id="t1137-azure",
            name="Azure Office Application Startup Detection",
            description=(
                "Azure detection for Office Application Startup. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.DEFENDER_ALERT,
            aws_service="n/a",
            azure_service="defender",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                defender_alert_types=[
                    "Suspicious inbox manipulation rules",
                    "Suspicious inbox forwarding",
                    "Suspicious OAuth app file download activities",
                ],
                azure_terraform_template="""# Microsoft Defender for Cloud Detection
# Office Application Startup (T1137)
# Microsoft Defender detects Office Application Startup activity

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

variable "location" {
  type        = string
  description = "Azure region for resources"
  default     = "uksouth"
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
  name                = "defender-t1137-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "DefAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Log Analytics query for Defender alerts
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "defender_detection" {
  name                = "defender-t1137"
  resource_group_name = var.resource_group_name
  location            = var.location

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

                    "Suspicious inbox manipulation rules",
                    "Suspicious inbox forwarding",
                    "Suspicious OAuth app file download activities"
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

  description = "Microsoft Defender detects Office Application Startup activity"
  display_name = "Defender: Office Application Startup"
  enabled      = true

  tags = {
    "mitre-technique" = "T1137"
    "detection-type"  = "security"
  }
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.defender_detection.id
}""",
                alert_severity="high",
                alert_title="Azure: Office Application Startup Detected",
                alert_description_template=(
                    "Office Application Startup activity detected. "
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
        "t1137-registry-monitoring",
        "t1137-aws-workspaces",
        "t1137-m365-macro",
        "t1137-gcp-workspace",
    ],
    total_effort_hours=11.0,
    coverage_improvement="+25% improvement for Persistence tactic in cloud-hosted Windows environments",
)
