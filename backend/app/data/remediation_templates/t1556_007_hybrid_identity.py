"""
T1556.007 - Modify Authentication Process: Hybrid Identity

Adversaries modify cloud authentication processes connected to on-premises user
identities to bypass authentication mechanisms, steal credentials, and maintain
persistent access in hybrid environments.
Used by APT29.
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
    technique_id="T1556.007",
    technique_name="Modify Authentication Process: Hybrid Identity",
    tactic_ids=["TA0006", "TA0005", "TA0003"],
    mitre_url="https://attack.mitre.org/techniques/T1556/007/",
    threat_context=ThreatContext(
        description=(
            "Adversaries modify cloud authentication processes connected to on-premises user "
            "identities to bypass authentication mechanisms, steal credentials, and maintain "
            "persistent access. This targets hybrid environments where identities span both "
            "on-premises Active Directory and cloud platforms (Azure Entra ID, AWS IAM Identity Center). "
            "Attackers exploit three primary synchronisation methods: Password Hash Synchronisation (PHS), "
            "Pass-Through Authentication (PTA), and Active Directory Federation Services (AD FS)."
        ),
        attacker_goal="Bypass hybrid authentication mechanisms to maintain persistent access and steal credentials",
        why_technique=[
            "Bypasses multi-factor authentication and conditional access policies",
            "Enables persistent access even after password resets",
            "Allows credential theft from hybrid identity synchronisation",
            "Difficult to detect without specific monitoring of hybrid components",
            "Provides access to both cloud and on-premises resources",
            "Often overlooked during incident response",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="rare",
        trend="increasing",
        severity_score=10,
        severity_reasoning=(
            "Extremely high severity due to complete bypass of authentication controls including MFA. "
            "Provides persistent access to both cloud and on-premises environments. Indicates advanced "
            "adversary with privileged access. Can compromise entire hybrid identity infrastructure."
        ),
        business_impact=[
            "Complete bypass of authentication and MFA controls",
            "Persistent unauthorised access to cloud and on-premises resources",
            "Mass credential theft from hybrid synchronisation services",
            "Compromise of federated identity trust relationships",
            "Severe compliance violations (SOC 2, ISO 27001, FedRAMP)",
            "Potential for organisation-wide identity infrastructure compromise",
        ],
        typical_attack_phase="persistence",
        often_precedes=["T1078.004", "T1530", "T1537", "T1087.004"],
        often_follows=["T1078.004", "T1098.001", "T1484"],
    ),
    detection_strategies=[
        # Strategy 1: Azure AD Connect PTA Agent Registration
        DetectionStrategy(
            strategy_id="t1556007-azure-pta-agent",
            name="Azure AD Connect PTA Agent Registration",
            description="Detect unauthorised Pass-Through Authentication (PTA) agent registrations in Azure Entra ID.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""# This detection is for Azure Entra ID audit logs exported to CloudWatch
fields @timestamp, activityDisplayName, initiatedBy.user.userPrincipalName, targetResources
| filter activityDisplayName = "Register connector"
| filter targetResources.0.type = "ServicePrincipal"
| filter targetResources.0.displayName like /PTA|PassthroughAuthentication/
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect unauthorised Azure AD PTA agent registration (requires Azure logs in CloudWatch)

Parameters:
  AzureAuditLogGroup:
    Type: String
    Description: CloudWatch log group containing Azure Entra ID audit logs
  AlertEmail:
    Type: String

Resources:
  # Step 1: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter for PTA agent registration
  PTAAgentFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref AzureAuditLogGroup
      FilterPattern: '{ $.activityDisplayName = "Register connector" && $.targetResources[0].displayName = "*PTA*" }'
      MetricTransformations:
        - MetricName: PTAAgentRegistrations
          MetricNamespace: Security/T1556
          MetricValue: "1"

  # Step 3: Alarm for PTA agent registration
  PTAAgentAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1556-007-PTAAgentRegistration
      AlarmDescription: Alert on unauthorised PTA agent registration
      MetricName: PTAAgentRegistrations
      Namespace: Security/T1556
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 0
      ComparisonOperator: GreaterThanThreshold
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref AlertTopic""",
                terraform_template="""# Detect unauthorised Azure AD PTA agent registration

variable "azure_audit_log_group" {
  type        = string
  description = "CloudWatch log group containing Azure Entra ID audit logs"
}

variable "alert_email" {
  type = string
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "pta_alerts" {
  name = "pta-agent-registration-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.pta_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for PTA agent registration
resource "aws_cloudwatch_log_metric_filter" "pta_agent" {
  name           = "pta-agent-registrations"
  log_group_name = var.azure_audit_log_group

  pattern = "{ $.activityDisplayName = \"Register connector\" && $.targetResources[0].displayName = \"*PTA*\" }"

  metric_transformation {
    name      = "PTAAgentRegistrations"
    namespace = "Security/T1556"
    value     = "1"
  }
}

# Step 3: Alarm for PTA agent registration
resource "aws_cloudwatch_metric_alarm" "pta_agent" {
  alarm_name          = "pta-agent-registration"
  metric_name         = "PTAAgentRegistrations"
  namespace           = "Security/T1556"
  statistic           = "Sum"
  period              = 300
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.pta_alerts.arn]
}""",
                alert_severity="critical",
                alert_title="Unauthorised PTA Agent Registered",
                alert_description_template=(
                    "Pass-Through Authentication agent registered by {initiatedBy}. "
                    "This may indicate hybrid identity compromise by advanced adversary."
                ),
                investigation_steps=[
                    "Verify if PTA agent registration was authorised and expected",
                    "Identify server where new PTA agent was registered",
                    "Review Azure Entra ID audit logs for Global Administrator activity",
                    "Check for other suspicious identity configuration changes",
                    "Examine the registering user's recent activity and source IP",
                    "Review all currently registered PTA agents in Azure portal",
                ],
                containment_actions=[
                    "Immediately unregister unauthorised PTA agent from Azure portal",
                    "Isolate the server running the malicious PTA agent",
                    "Reset credentials for Global Administrator accounts",
                    "Enable MFA for all privileged accounts if not already enabled",
                    "Review and revoke active Azure AD sessions",
                    "Conduct forensic analysis of compromised PTA server",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="PTA agent registrations are extremely rare; all events warrant investigation",
            detection_coverage="100% - catches all PTA agent registrations if Azure logs exported",
            evasion_considerations="Requires Azure Entra ID audit logs exported to AWS CloudWatch",
            implementation_effort=EffortLevel.HIGH,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=[
                "Azure Entra ID audit logs exported to CloudWatch",
                "Hybrid identity setup",
            ],
        ),
        # Strategy 2: AD FS Configuration File Modifications
        DetectionStrategy(
            strategy_id="t1556007-adfs-config-change",
            name="AD FS Configuration File Modification",
            description="Detect modifications to AD FS configuration files that could load malicious DLLs.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""# This detection is for Windows Server logs from AD FS servers sent to CloudWatch
fields @timestamp, EventID, TargetFilename, User, Computer
| filter Computer like /ADFS/
| filter TargetFilename like /Microsoft.IdentityServer.Servicehost|FederationMetadata.xml|Microsoft.IdentityServer.dll/
| filter EventID in [4663, 4670, 4660, 5145]
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect AD FS configuration file modifications (requires Windows logs in CloudWatch)

Parameters:
  ADFSLogGroup:
    Type: String
    Description: CloudWatch log group containing AD FS server Windows event logs
  AlertEmail:
    Type: String

Resources:
  # Step 1: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter for AD FS config changes
  ADFSConfigFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref ADFSLogGroup
      FilterPattern: '{ $.EventID = 4663 || $.EventID = 4670 && $.TargetFilename = "*Microsoft.IdentityServer*" }'
      MetricTransformations:
        - MetricName: ADFSConfigChanges
          MetricNamespace: Security/T1556
          MetricValue: "1"

  # Step 3: Alarm for AD FS config changes
  ADFSConfigAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1556-007-ADFSConfigChange
      AlarmDescription: Alert on AD FS configuration file modifications
      MetricName: ADFSConfigChanges
      Namespace: Security/T1556
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 0
      ComparisonOperator: GreaterThanThreshold
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref AlertTopic""",
                terraform_template="""# Detect AD FS configuration file modifications

variable "adfs_log_group" {
  type        = string
  description = "CloudWatch log group containing AD FS Windows event logs"
}

variable "alert_email" {
  type = string
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "adfs_alerts" {
  name = "adfs-config-modification-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.adfs_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for AD FS config changes
resource "aws_cloudwatch_log_metric_filter" "adfs_config" {
  name           = "adfs-config-changes"
  log_group_name = var.adfs_log_group

  pattern = "{ $.EventID = 4663 || $.EventID = 4670 && $.TargetFilename = \"*Microsoft.IdentityServer*\" }"

  metric_transformation {
    name      = "ADFSConfigChanges"
    namespace = "Security/T1556"
    value     = "1"
  }
}

# Step 3: Alarm for AD FS config changes
resource "aws_cloudwatch_metric_alarm" "adfs_config" {
  alarm_name          = "adfs-config-modifications"
  metric_name         = "ADFSConfigChanges"
  namespace           = "Security/T1556"
  statistic           = "Sum"
  period              = 300
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.adfs_alerts.arn]
}""",
                alert_severity="critical",
                alert_title="AD FS Configuration Modified",
                alert_description_template=(
                    "AD FS configuration file {TargetFilename} modified by {User} on {Computer}. "
                    "May indicate DLL injection for authentication bypass."
                ),
                investigation_steps=[
                    "Identify what AD FS configuration file was modified",
                    "Check for unsigned or suspicious DLLs in AD FS directories",
                    "Review who made the modification and their access history",
                    "Examine AD FS service host process for loaded modules",
                    "Check AD FS event logs for unusual token issuance patterns",
                    "Review federation metadata for unauthorised changes",
                ],
                containment_actions=[
                    "Immediately isolate the AD FS server from network",
                    "Restore AD FS configuration from known good backup",
                    "Remove any malicious DLLs from AD FS directories",
                    "Reset AD FS service account credentials",
                    "Revoke all active federated authentication tokens",
                    "Conduct full forensic analysis of AD FS server",
                    "Review and reset signing certificates if compromised",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Exclude planned maintenance windows and authorised patching activities",
            detection_coverage="95% - catches file-level modifications if Windows auditing enabled",
            evasion_considerations="Requires Windows object access auditing enabled on AD FS servers",
            implementation_effort=EffortLevel.HIGH,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$15-25",
            prerequisites=[
                "AD FS servers logging to CloudWatch",
                "Windows object access auditing enabled",
            ],
        ),
        # Strategy 3: AWS IAM Identity Center (SSO) Federation Changes
        DetectionStrategy(
            strategy_id="t1556007-aws-sso-federation",
            name="AWS IAM Identity Center Federation Modification",
            description="Detect changes to identity source or federation settings in AWS IAM Identity Center.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.sso"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventName": [
                            "UpdateIdentitySource",
                            "CreateIdentitySource",
                            "DeleteIdentitySource",
                            "UpdateApplication",
                            "AttachManagedPolicyToPermissionSet",
                        ]
                    },
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect IAM Identity Center federation changes

Parameters:
  AlertEmail:
    Type: String

Resources:
  # Step 1: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: EventBridge rule for Identity Center changes
  SSOFederationRule:
    Type: AWS::Events::Rule
    Properties:
      Name: T1556-007-SSOFederationChanges
      Description: Alert on IAM Identity Center federation modifications
      EventPattern:
        source: [aws.sso]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName:
            - UpdateIdentitySource
            - CreateIdentitySource
            - DeleteIdentitySource
            - UpdateApplication
            - AttachManagedPolicyToPermissionSet
      State: ENABLED
      Targets:
        - Id: Alert
          Arn: !Ref AlertTopic

  # Step 3: Topic policy
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
            Resource: !Ref AlertTopic""",
                terraform_template="""# Detect IAM Identity Center federation changes

variable "alert_email" {
  type = string
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "sso_alerts" {
  name = "sso-federation-modification-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.sso_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule for Identity Center changes
resource "aws_cloudwatch_event_rule" "sso_federation" {
  name        = "sso-federation-changes"
  description = "Alert on IAM Identity Center federation modifications"

  event_pattern = jsonencode({
    source      = ["aws.sso"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "UpdateIdentitySource",
        "CreateIdentitySource",
        "DeleteIdentitySource",
        "UpdateApplication",
        "AttachManagedPolicyToPermissionSet"
      ]
    }
  })
}

# Dead Letter Queue for failed events
resource "aws_sqs_queue" "dlq" {
  name                      = "sso-federation-dlq"
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
        ArnEquals = { "aws:SourceArn" = aws_cloudwatch_event_rule.sso_federation.arn }
      }
    }]
  })
}

# EventBridge target with retry and DLQ
resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.sso_federation.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.sso_alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
  }
}

# Step 3: Topic policy
data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_events" {
  arn = aws_sns_topic.sso_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.sso_alerts.arn
    Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}""",
                alert_severity="critical",
                alert_title="IAM Identity Center Federation Modified",
                alert_description_template=(
                    "IAM Identity Center identity source or federation modified. "
                    "Event: {eventName}. Actor: {userIdentity.principalId}."
                ),
                investigation_steps=[
                    "Review what identity source or federation setting was changed",
                    "Verify if change was authorised and documented",
                    "Check who made the change and from which source IP",
                    "Review CloudTrail for other SSO configuration changes",
                    "Examine permission set modifications around the same time",
                    "Check for new SAML or OIDC identity provider configurations",
                ],
                containment_actions=[
                    "Revert identity source to known good configuration",
                    "Review and remove unauthorised identity sources",
                    "Disable compromised IAM Identity Center instance if needed",
                    "Reset credentials for accounts with SSO admin access",
                    "Review and revoke active SSO sessions",
                    "Enable CloudTrail insights for unusual SSO API activity",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Federation changes should be rare and well-documented",
            detection_coverage="100% - catches all IAM Identity Center federation modifications",
            evasion_considerations="Cannot evade if using AWS APIs; requires CloudTrail enabled",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled", "IAM Identity Center configured"],
        ),
        # Strategy 4: Suspicious DLL Loads in LSASS
        DetectionStrategy(
            strategy_id="t1556007-lsass-dll-load",
            name="Suspicious DLL Load in LSASS Process",
            description="Detect unsigned or suspicious DLL modules loaded into LSASS or AD FS processes.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""# This detection is for Sysmon logs (Event ID 7) from hybrid identity servers
fields @timestamp, EventID, ImageLoaded, Signed, Signature, ProcessName, Computer
| filter EventID = 7
| filter ProcessName like /lsass.exe|Microsoft.IdentityServer.ServiceHost.exe|AzureADConnectAuthenticationAgentService.exe/
| filter Signed = "false" or Signature = ""
| sort @timestamp desc""",
                terraform_template="""# Detect suspicious DLL loads in hybrid identity processes

variable "hybrid_identity_log_group" {
  type        = string
  description = "CloudWatch log group containing Sysmon logs from hybrid identity servers"
}

variable "alert_email" {
  type = string
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "dll_alerts" {
  name = "hybrid-identity-dll-load-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.dll_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for unsigned DLL loads
resource "aws_cloudwatch_log_metric_filter" "unsigned_dll" {
  name           = "unsigned-dll-loads"
  log_group_name = var.hybrid_identity_log_group

  pattern = "{ $.EventID = 7 && ($.ProcessName = \"*lsass.exe*\" || $.ProcessName = \"*Microsoft.IdentityServer*\" || $.ProcessName = \"*AzureADConnect*\") && $.Signed = \"false\" }"

  metric_transformation {
    name      = "UnsignedDLLLoads"
    namespace = "Security/T1556"
    value     = "1"
  }
}

# Step 3: Alarm for suspicious DLL loads
resource "aws_cloudwatch_metric_alarm" "dll_load" {
  alarm_name          = "suspicious-dll-loads"
  metric_name         = "UnsignedDLLLoads"
  namespace           = "Security/T1556"
  statistic           = "Sum"
  period              = 300
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.dll_alerts.arn]
}""",
                alert_severity="critical",
                alert_title="Suspicious DLL Loaded in Identity Process",
                alert_description_template=(
                    "Unsigned DLL {ImageLoaded} loaded into {ProcessName} on {Computer}. "
                    "May indicate malicious DLL injection for credential theft."
                ),
                investigation_steps=[
                    "Identify the unsigned DLL that was loaded",
                    "Check DLL file properties, hash, and VirusTotal analysis",
                    "Review when the DLL was created or modified",
                    "Examine process tree and parent process",
                    "Check for other unsigned DLLs in system directories",
                    "Review recent authentication events for anomalies",
                ],
                containment_actions=[
                    "Immediately isolate the affected server",
                    "Remove the malicious DLL from the system",
                    "Restart affected services after DLL removal",
                    "Reset credentials for all hybrid identity sync accounts",
                    "Conduct memory dump analysis of affected processes",
                    "Review all authentication events since DLL load time",
                    "Force password reset for all synchronised accounts",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known legitimate unsigned DLLs; investigate all others",
            detection_coverage="90% - catches DLL injection if Sysmon deployed",
            evasion_considerations="Requires Sysmon deployed on hybrid identity servers",
            implementation_effort=EffortLevel.HIGH,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=[
                "Sysmon deployed on hybrid identity servers",
                "Sysmon logs in CloudWatch",
            ],
        ),
        # Strategy 5: GCP Workspace Directory Sync Configuration Changes
        DetectionStrategy(
            strategy_id="t1556007-gcp-directory-sync",
            name="GCP Directory Sync Configuration Changes",
            description="Detect modifications to Google Cloud Directory Sync (GCDS) or SAML SSO configuration.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.serviceName="admin.googleapis.com"
protoPayload.methodName=~"google.admin.AdminService.changeSamlSsoSettings|google.admin.AdminService.changeApplicationSettings"
OR protoPayload.metadata.event.eventName="SSO_PROFILE_UPDATED"''',
                gcp_terraform_template="""# GCP: Detect Directory Sync and SSO configuration changes

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Hybrid Identity Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for SSO config changes
resource "google_logging_metric" "sso_config_changes" {
  name   = "hybrid-identity-sso-changes"
  filter = <<-EOT
    protoPayload.serviceName="admin.googleapis.com"
    (protoPayload.methodName=~"google.admin.AdminService.changeSamlSsoSettings|google.admin.AdminService.changeApplicationSettings"
    OR protoPayload.metadata.event.eventName="SSO_PROFILE_UPDATED")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy for SSO changes
resource "google_monitoring_alert_policy" "sso_config" {
  display_name = "Hybrid Identity SSO Configuration Changed"
  combiner     = "OR"

  conditions {
    display_name = "SSO configuration modified"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.sso_config_changes.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  documentation {
    content = "Hybrid identity or SAML SSO configuration was modified. Verify this change was authorised."
  }
}""",
                alert_severity="critical",
                alert_title="GCP: Hybrid Identity Configuration Modified",
                alert_description_template=(
                    "Directory sync or SAML SSO configuration modified in project {projectId}. "
                    "Method: {methodName}. Actor: {principalEmail}."
                ),
                investigation_steps=[
                    "Review what SSO or directory sync setting was changed",
                    "Verify if change was authorised and documented",
                    "Check who made the change (principalEmail)",
                    "Review other administrative actions by the same actor",
                    "Check for unauthorised SAML identity provider additions",
                    "Examine recent authentication patterns for anomalies",
                ],
                containment_actions=[
                    "Revert SSO configuration to known good state",
                    "Remove unauthorised SAML identity providers",
                    "Disable directory sync temporarily if compromised",
                    "Reset credentials for super admin accounts",
                    "Review and revoke active SSO sessions",
                    "Enable organisation policy constraints for SSO changes",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="SSO configuration changes should be rare and documented",
            detection_coverage="95% - catches SSO and directory sync modifications",
            evasion_considerations="Very difficult to evade when using Workspace Admin API",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-15",
            prerequisites=[
                "Google Workspace",
                "Admin audit logs enabled",
                "SSO configured",
            ],
        ),
    ],
    recommended_order=[
        "t1556007-aws-sso-federation",
        "t1556007-gcp-directory-sync",
        "t1556007-azure-pta-agent",
        "t1556007-adfs-config-change",
        "t1556007-lsass-dll-load",
    ],
    total_effort_hours=8.5,
    coverage_improvement="+25% improvement for Credential Access and Persistence tactics in hybrid environments",
)
