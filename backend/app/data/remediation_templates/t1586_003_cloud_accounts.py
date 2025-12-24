"""
T1586.003 - Compromise Accounts: Cloud Accounts

Adversaries compromise cloud accounts before initial access to enable operations.
Used for data exfiltration, tool deployment, infrastructure acquisition, and
messaging abuse. Used by APT29, APT41.
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
    technique_id="T1586.003",
    technique_name="Compromise Accounts: Cloud Accounts",
    tactic_ids=["TA0042"],  # Resource Development
    mitre_url="https://attack.mitre.org/techniques/T1586/003/",
    threat_context=ThreatContext(
        description=(
            "Adversaries compromise cloud accounts before engaging with a victim "
            "organisation to support operations without maintaining their own infrastructure. "
            "Compromised cloud accounts are used for data exfiltration via cloud storage, "
            "tool deployment, infrastructure acquisition, and messaging abuse through "
            "services like Twilio, SendGrid, and AWS messaging platforms."
        ),
        attacker_goal="Obtain cloud account access for operational infrastructure and evading attribution",
        why_technique=[
            "Avoids maintaining attacker-owned infrastructure",
            "Leverages trusted cloud providers for legitimacy",
            "Enables residential proxy networks for obfuscation",
            "Facilitates command and control operations",
            "Provides storage for exfiltrated data",
        ],
        known_threat_actors=["APT29", "APT41"],
        recent_campaigns=[
            Campaign(
                name="APT29 Azure VM Proxies",
                year=2024,
                description="Utilised compromised Azure Virtual Machines as residential proxies to obfuscate access to victim environments",
                reference_url="https://attack.mitre.org/groups/G0016/",
            ),
            Campaign(
                name="APT41 DUST Google Workspace C2",
                year=2024,
                description="Employed compromised Google Workspace accounts for command and control operations",
                reference_url="https://attack.mitre.org/campaigns/C0040/",
            ),
        ],
        prevalence="common",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "Pre-compromise technique that enables multiple attack vectors. "
            "Difficult to detect as activity occurs outside organisational visibility. "
            "Can lead to significant operational security and attribution advantages for adversaries."
        ),
        business_impact=[
            "Unauthorised cloud resource usage",
            "Reputation damage from abuse",
            "Data exfiltration via cloud storage",
            "Hosting of malicious infrastructure",
            "Phishing and spam campaigns",
        ],
        typical_attack_phase="resource_development",
        often_precedes=["T1078.004", "T1567", "T1102", "T1071"],
        often_follows=["T1589", "T1590", "T1598"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1586-003-aws-iam-anomaly",
            name="AWS IAM Unusual Authentication Patterns",
            description="Detect anomalous IAM authentication patterns indicating compromised credentials.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.principalId, sourceIPAddress, userAgent, eventName
| filter eventName like /Console|AssumeRole|GetSessionToken/
| filter sourceIPAddress not like /^(10\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.|192\\.168\\.)/
| stats count(*) as authCount, count_distinct(sourceIPAddress) as ipCount,
  count_distinct(userAgent) as uaCount by userIdentity.principalId, bin(1h)
| filter ipCount > 3 or uaCount > 2
| sort authCount desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect compromised IAM credentials via anomalous authentication patterns

Parameters:
  CloudTrailLogGroup:
    Type: String
    Description: CloudTrail log group name
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # Step 1: Create SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: IAM Anomaly Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Create metric filter for unusual authentication patterns
  AnomalousAuthFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventName = "ConsoleLogin" || $.eventName = "AssumeRole") && $.sourceIPAddress != "10.*" && $.sourceIPAddress != "172.16.*" && $.sourceIPAddress != "192.168.*" }'
      MetricTransformations:
        - MetricName: AnomalousIAMAuth
          MetricNamespace: Security/IAM
          MetricValue: "1"
          DefaultValue: 0

  # Step 3: Create alarm for high-frequency anomalous authentication
  AnomalousAuthAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: CompromisedIAMCredentials
      AlarmDescription: Detects unusual authentication patterns indicating potential credential compromise
      MetricName: AnomalousIAMAuth
      Namespace: Security/IAM
      Statistic: Sum
      Period: 300
      Threshold: 5
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      AlarmActions: [!Ref AlertTopic]
      TreatMissingData: notBreaching""",
                terraform_template="""# AWS: Detect compromised IAM credentials via anomalous authentication

variable "cloudtrail_log_group" {
  description = "CloudTrail log group name"
  type        = string
}

variable "alert_email" {
  description = "Email for security alerts"
  type        = string
}

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "iam_anomaly_alerts" {
  name         = "iam-anomaly-alerts"
  display_name = "IAM Anomaly Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.iam_anomaly_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for unusual authentication patterns
resource "aws_cloudwatch_log_metric_filter" "anomalous_auth" {
  name           = "anomalous-iam-auth"
  log_group_name = var.cloudtrail_log_group
  # Detect external logins and role assumptions
  pattern        = "{ ($.eventName = \"ConsoleLogin\" || $.eventName = \"AssumeRole\") && $.sourceIPAddress != \"10.*\" && $.sourceIPAddress != \"172.16.*\" && $.sourceIPAddress != \"192.168.*\" }"

  metric_transformation {
    name      = "AnomalousIAMAuth"
    namespace = "Security/IAM"
    value     = "1"
    default_value = 0
  }
}

# Step 3: Create alarm for high-frequency anomalous authentication
resource "aws_cloudwatch_metric_alarm" "compromised_credentials" {
  alarm_name          = "CompromisedIAMCredentials"
  alarm_description   = "Detects unusual authentication patterns indicating potential credential compromise"
  metric_name         = "AnomalousIAMAuth"
  namespace           = "Security/IAM"
  statistic           = "Sum"
  period              = 300
  threshold           = 5
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.iam_anomaly_alerts.arn]
  treat_missing_data  = "notBreaching"
}""",
                alert_severity="high",
                alert_title="Potential Compromised IAM Credentials",
                alert_description_template="Unusual authentication patterns detected for {principalId} from multiple IPs or user agents.",
                investigation_steps=[
                    "Review authentication source IPs and geolocations",
                    "Check if user agent patterns are consistent with legitimate use",
                    "Review recent IAM activity and API calls",
                    "Verify with account owner if access was authorised",
                    "Check for concurrent sessions from different locations",
                    "Review CloudTrail logs for privilege escalation attempts",
                ],
                containment_actions=[
                    "Disable compromised IAM user or rotate credentials immediately",
                    "Revoke active sessions using aws iam delete-access-key",
                    "Enable MFA if not already configured",
                    "Review and remove any unauthorised resources created",
                    "Check for backdoor accounts or access keys",
                    "Notify security team and begin incident response",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Tune IP ranges for legitimate VPN/office networks and expected user agent patterns",
            detection_coverage="60% - detects authentication anomalies but may miss credential-only compromises",
            evasion_considerations="Attackers using stolen sessions or matching legitimate patterns may evade",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30-60 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail with CloudWatch Logs integration enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1586-003-aws-guardduty",
            name="AWS GuardDuty Credential Compromise Detection",
            description="Leverage GuardDuty findings for compromised credential detection.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, detail.type, detail.severity, detail.resource.accessKeyDetails.userName
| filter detail.type like /UnauthorizedAccess|Stealth|CredentialAccess/
| filter detail.type like /IAMUser|Root/
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Alert on GuardDuty credential compromise findings

Parameters:
  AlertEmail:
    Type: String
    Description: Email for GuardDuty alerts

Resources:
  # Step 1: Create SNS topic for GuardDuty alerts
  GuardDutyAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: GuardDuty Credential Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Create EventBridge rule for credential compromise findings
  GuardDutyCredentialRule:
    Type: AWS::Events::Rule
    Properties:
      Name: GuardDutyCredentialCompromise
      Description: Detect GuardDuty findings indicating credential compromise
      EventPattern:
        source:
          - aws.guardduty
        detail-type:
          - GuardDuty Finding
        detail:
          type:
            - prefix: UnauthorizedAccess:IAMUser
            - prefix: Stealth:IAMUser
            - prefix: CredentialAccess
      State: ENABLED
      Targets:
        - Arn: !Ref GuardDutyAlertTopic
          Id: GuardDutyAlertTarget

  # Step 3: Grant EventBridge permission to publish to SNS
  EventBridgeToSnsPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref GuardDutyAlertTopic]
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref GuardDutyAlertTopic""",
                terraform_template="""# AWS: Alert on GuardDuty credential compromise findings

variable "alert_email" {
  description = "Email for GuardDuty alerts"
  type        = string
}

# Step 1: Create SNS topic for GuardDuty alerts
resource "aws_sns_topic" "guardduty_alerts" {
  name         = "guardduty-credential-alerts"
  display_name = "GuardDuty Credential Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.guardduty_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create EventBridge rule for credential compromise findings
resource "aws_cloudwatch_event_rule" "guardduty_credential" {
  name        = "guardduty-credential-compromise"
  description = "Detect GuardDuty findings indicating credential compromise"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [
        { prefix = "UnauthorizedAccess:IAMUser" },
        { prefix = "Stealth:IAMUser" },
        { prefix = "CredentialAccess" }
      ]
    }
  })
}

# Step 3: Create EventBridge target to publish to SNS
resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.guardduty_credential.name
  target_id = "GuardDutyAlertTarget"
  arn       = aws_sns_topic.guardduty_alerts.arn
}

resource "aws_sns_topic_policy" "guardduty_publish" {
  arn = aws_sns_topic.guardduty_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "events.amazonaws.com"
      }
      Action   = "SNS:Publish"
      Resource = aws_sns_topic.guardduty_alerts.arn
    }]
  })
}""",
                alert_severity="critical",
                alert_title="GuardDuty: Compromised Credentials Detected",
                alert_description_template="GuardDuty detected credential compromise: {finding_type}.",
                investigation_steps=[
                    "Review GuardDuty finding details and severity",
                    "Identify affected IAM user or access key",
                    "Check CloudTrail for recent activity by compromised credentials",
                    "Review resource access and API calls made",
                    "Determine compromise timeline and scope",
                    "Check for data exfiltration or resource manipulation",
                ],
                containment_actions=[
                    "Immediately disable affected access keys",
                    "Rotate all credentials for affected user",
                    "Terminate active sessions",
                    "Review and remove unauthorised resources",
                    "Enable MFA on affected accounts",
                    "Follow GuardDuty remediation guidance",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="GuardDuty findings are generally high-fidelity",
            detection_coverage="80% - comprehensive ML-based detection",
            evasion_considerations="Sophisticated attackers mimicking normal behaviour may evade",
            implementation_effort=EffortLevel.LOW,
            implementation_time="15-30 minutes",
            estimated_monthly_cost="$10-50",
            prerequisites=["AWS GuardDuty enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1586-003-aws-access-analyzer",
            name="AWS IAM Access Analyzer External Access",
            description="Detect external access to AWS resources indicating potential account compromise.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="accessanalyzer",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, detail.findingType, detail.resourceType, detail.principal
| filter detail.status = "ACTIVE"
| filter detail.isPublic = true or detail.principal.AWS not like /^arn:aws:iam::\\d{12}:/
| sort @timestamp desc""",
                terraform_template="""# AWS: Detect external resource access via IAM Access Analyzer

variable "alert_email" {
  description = "Email for Access Analyzer alerts"
  type        = string
}

# Step 1: Enable IAM Access Analyzer
resource "aws_accessanalyzer_analyzer" "account" {
  analyzer_name = "account-analyzer"
  type          = "ACCOUNT"
}

# Step 2: Create SNS topic for alerts
resource "aws_sns_topic" "access_analyzer_alerts" {
  name         = "access-analyzer-alerts"
  display_name = "IAM Access Analyzer Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.access_analyzer_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 3: Create EventBridge rule for external access findings
resource "aws_cloudwatch_event_rule" "external_access" {
  name        = "access-analyzer-external-access"
  description = "Detect external access to AWS resources"

  event_pattern = jsonencode({
    source      = ["aws.access-analyzer"]
    detail-type = ["Access Analyzer Finding"]
    detail = {
      status = ["ACTIVE"]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.external_access.name
  target_id = "AccessAnalyzerTarget"
  arn       = aws_sns_topic.access_analyzer_alerts.arn
}

resource "aws_sns_topic_policy" "eventbridge_publish" {
  arn = aws_sns_topic.access_analyzer_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "events.amazonaws.com"
      }
      Action   = "SNS:Publish"
      Resource = aws_sns_topic.access_analyzer_alerts.arn
    }]
  })
}""",
                alert_severity="high",
                alert_title="External Access to AWS Resources Detected",
                alert_description_template="IAM Access Analyzer detected external access to {resourceType}.",
                investigation_steps=[
                    "Review Access Analyzer finding details",
                    "Identify resource with external access",
                    "Determine if external access is authorised",
                    "Check resource policy and permissions",
                    "Review CloudTrail for policy modification events",
                    "Verify principal accessing the resource",
                ],
                containment_actions=[
                    "Remove unauthorised external access permissions",
                    "Update resource policies to restrict access",
                    "Review and audit all cross-account access",
                    "Enable SCPs to prevent unauthorised sharing",
                    "Document legitimate external access requirements",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Maintain allowlist of legitimate external access patterns",
            detection_coverage="70% - detects resource-level external access",
            evasion_considerations="Internal compromises without external resource access may not be detected",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-15",
            prerequisites=["IAM Access Analyzer enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1586-003-gcp-audit-anomaly",
            name="GCP Audit Log Unusual Authentication Patterns",
            description="Detect anomalous authentication patterns in GCP indicating compromised accounts.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="audited_resource"
protoPayload.methodName=~"google.login|SetIamPolicy|GenerateAccessToken"
protoPayload.authenticationInfo.principalEmail!=""
NOT protoPayload.requestMetadata.callerIp=~"^(10\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.|192\\.168\\.)"''',
                gcp_terraform_template="""# GCP: Detect compromised credentials via anomalous authentication

variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "alert_email" {
  description = "Email for security alerts"
  type        = string
}

# Step 1: Create notification channel for alerts
resource "google_monitoring_notification_channel" "email" {
  project      = var.project_id
  display_name = "Security Alerts Email"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log-based metric for anomalous authentication
resource "google_logging_metric" "anomalous_auth" {
  project = var.project_id
  name    = "anomalous-authentication"
  filter  = <<-EOT
    resource.type="audited_resource"
    protoPayload.methodName=~"google.login|SetIamPolicy|GenerateAccessToken"
    protoPayload.authenticationInfo.principalEmail!=""
    NOT protoPayload.requestMetadata.callerIp=~"^(10\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.|192\\.168\\.)"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "principal_email"
      value_type  = "STRING"
      description = "User email address"
    }
  }

  label_extractors = {
    "principal_email" = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
  }
}

# Step 3: Create alert policy for credential compromise
resource "google_monitoring_alert_policy" "compromised_credentials" {
  project      = var.project_id
  display_name = "Potential Compromised GCP Credentials"
  combiner     = "OR"

  conditions {
    display_name = "Unusual authentication frequency"
    condition_threshold {
      filter          = "resource.type=\"global\" AND metric.type=\"logging.googleapis.com/user/${google_logging_metric.anomalous_auth.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 5
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "86400s"
  }
}""",
                alert_severity="high",
                alert_title="GCP: Potential Compromised Credentials",
                alert_description_template="Unusual authentication patterns detected for {principal_email}.",
                investigation_steps=[
                    "Review audit log entries for affected principal",
                    "Check source IP addresses and geolocations",
                    "Verify if authentication attempts were authorised",
                    "Review recent IAM policy changes",
                    "Check for privilege escalation attempts",
                    "Review resource access and API calls",
                ],
                containment_actions=[
                    "Disable compromised user account immediately",
                    "Revoke service account keys if affected",
                    "Force password reset for user accounts",
                    "Enable 2FA if not already configured",
                    "Review and remove unauthorised IAM bindings",
                    "Audit all resources for unauthorised changes",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude legitimate VPN and office IP ranges from monitoring",
            detection_coverage="60% - detects authentication anomalies",
            evasion_considerations="Attackers using stolen tokens or matching patterns may evade",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-20",
            prerequisites=["GCP Audit Logs enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1586-003-gcp-sec-command",
            name="GCP Security Command Centre Threat Detection",
            description="Leverage Security Command Centre for compromised account detection.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="security_command_center",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="security_finding"
protoPayload.response.finding.category=~"Persistence|Credential Access|Initial Access"
severity=~"HIGH|CRITICAL"''',
                gcp_terraform_template="""# GCP: Alert on Security Command Centre credential findings

variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "organisation_id" {
  description = "GCP organisation ID"
  type        = string
}

variable "alert_email" {
  description = "Email for SCC alerts"
  type        = string
}

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "email" {
  project      = var.project_id
  display_name = "SCC Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log-based metric for credential findings
resource "google_logging_metric" "credential_findings" {
  project = var.project_id
  name    = "scc-credential-findings"
  filter  = <<-EOT
    resource.type="security_finding"
    protoPayload.response.finding.category=~"Persistence|Credential Access|Initial Access"
    severity=~"HIGH|CRITICAL"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Create alert policy for critical SCC findings
resource "google_monitoring_alert_policy" "scc_credential_alerts" {
  project      = var.project_id
  display_name = "SCC Credential Compromise Alerts"
  combiner     = "OR"

  conditions {
    display_name = "High-severity credential findings"
    condition_threshold {
      filter          = "resource.type=\"global\" AND metric.type=\"logging.googleapis.com/user/${google_logging_metric.credential_findings.name}\""
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
    auto_close = "86400s"
  }
}""",
                alert_severity="critical",
                alert_title="GCP SCC: Credential Compromise Detected",
                alert_description_template="Security Command Centre detected credential compromise activity.",
                investigation_steps=[
                    "Review SCC finding details and severity",
                    "Identify affected accounts and resources",
                    "Check audit logs for suspicious activity",
                    "Review IAM policy changes and access grants",
                    "Determine scope and timeline of compromise",
                    "Check for lateral movement indicators",
                ],
                containment_actions=[
                    "Disable compromised accounts immediately",
                    "Rotate all affected credentials and keys",
                    "Review and remove unauthorised IAM bindings",
                    "Enable 2FA on all accounts",
                    "Follow SCC remediation recommendations",
                    "Conduct full security audit",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="SCC findings are generally high-fidelity",
            detection_coverage="85% - comprehensive threat detection",
            evasion_considerations="Zero-day techniques may evade initial detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$50-200",
            prerequisites=["Security Command Centre Premium enabled"],
        ),
    ],
    recommended_order=[
        "t1586-003-aws-guardduty",
        "t1586-003-gcp-sec-command",
        "t1586-003-aws-iam-anomaly",
        "t1586-003-gcp-audit-anomaly",
        "t1586-003-aws-access-analyzer",
    ],
    total_effort_hours=4.5,
    coverage_improvement="+25% improvement for Resource Development tactic",
)
