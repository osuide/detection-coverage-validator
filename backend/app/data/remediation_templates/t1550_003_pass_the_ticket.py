"""
T1550.003 - Use Alternate Authentication Material: Pass the Ticket

Adversaries leverage stolen Kerberos tickets to authenticate and move laterally
without requiring account passwords. In cloud environments, this includes detecting
ticket-based authentication abuse in hybrid cloud deployments and Active Directory
integrated cloud services.
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
    technique_id="T1550.003",
    technique_name="Use Alternate Authentication Material: Pass the Ticket",
    tactic_ids=["TA0005", "TA0008"],
    mitre_url="https://attack.mitre.org/techniques/T1550/003/",
    threat_context=ThreatContext(
        description=(
            "Adversaries leverage stolen Kerberos tickets to authenticate to systems without "
            "requiring passwords. This includes Service Tickets (TGS) for specific resources, "
            "Ticket Granting Tickets (TGT) for broader access, Silver Tickets forged with "
            "service account credentials, and Golden Tickets created using KRBTGT hashes. "
            "In cloud environments, this primarily affects hybrid deployments with Active Directory "
            "integration, AWS Managed Microsoft AD, Azure AD Domain Services, and on-premises "
            "workloads extended to cloud infrastructure."
        ),
        attacker_goal="Authenticate and move laterally using stolen Kerberos tickets without passwords",
        why_technique=[
            "Bypasses password-based authentication controls and monitoring",
            "Kerberos tickets are valid until expiration, providing persistent access",
            "Golden Tickets can provide domain-wide access for extended periods",
            "Legitimate ticket usage makes detection challenging",
            "Tickets can be injected into processes without triggering typical authentication logs",
            "Enables lateral movement to cloud-connected resources and hybrid environments",
        ],
        known_threat_actors=[],
        recent_campaigns=[
            Campaign(
                name="APT29 Kerberos Abuse",
                year=2023,
                description="APT29 used Kerberos ticket attacks for lateral movement across hybrid cloud environments",
                reference_url="https://attack.mitre.org/groups/G0016/",
            ),
            Campaign(
                name="BRONZE BUTLER Forged Tickets",
                year=2022,
                description="Created forged TGT and TGS tickets for administrative persistence in enterprise networks",
                reference_url="https://attack.mitre.org/groups/G0060/",
            ),
            Campaign(
                name="APT32 Remote Access",
                year=2021,
                description="Successfully gained remote access to cloud-connected systems via pass the ticket attacks",
                reference_url="https://attack.mitre.org/groups/G0050/",
            ),
        ],
        prevalence="moderate",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "Pass the Ticket attacks enable significant lateral movement with legitimate credentials. "
            "Golden Tickets, created using KRBTGT account hashes, can provide domain-wide access "
            "for months if not detected. In hybrid cloud environments, this technique allows "
            "attackers to pivot from on-premises to cloud resources, bypassing perimeter security. "
            "Detection is challenging as ticket usage appears legitimate."
        ),
        business_impact=[
            "Unauthorised access to cloud-connected resources and hybrid systems",
            "Lateral movement across domain-joined cloud instances",
            "Privilege escalation using forged or stolen administrative tickets",
            "Long-term persistent access via Golden Tickets",
            "Bypassing multi-factor authentication on Kerberos-authenticated systems",
            "Access to cloud-integrated Active Directory services and resources",
        ],
        typical_attack_phase="lateral_movement",
        often_precedes=["T1021", "T1570", "T1087"],
        often_follows=["T1003", "T1558"],
    ),
    detection_strategies=[
        # Strategy 1: AWS Managed Microsoft AD Monitoring
        DetectionStrategy(
            strategy_id="t1550003-aws-mad-monitoring",
            name="AWS Managed Microsoft AD Kerberos Monitoring",
            description=(
                "Monitor AWS Managed Microsoft AD for suspicious Kerberos authentication "
                "patterns including service ticket requests without corresponding logons, "
                "unusual ticket encryption types, and anomalous authentication timing."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="directory_service",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query=r"""fields @timestamp, @message, eventID, logon_type, auth_package
| filter eventID in [4768, 4769, 4770, 4624, 4672]
| parse @message /EventID=(?<event_id>\d+).*Account\sName:\s+(?<account>[^\s]+).*Client\sAddress:\s+(?<client_ip>[0-9\.]+)/
| stats count(*) as event_count,
        count_distinct(event_id) as unique_events,
        earliest(@timestamp) as first_seen,
        latest(@timestamp) as last_seen
  by account, client_ip, bin(10m)
| filter (event_id = "4769" and unique_events = 1) or event_count > 50
| sort event_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Monitor AWS Managed Microsoft AD for Pass the Ticket attacks

Parameters:
  DirectoryLogGroup:
    Type: String
    Description: CloudWatch log group for Managed AD security logs
    Default: /aws/directoryservice/d-*/security
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # Step 1: Create metric filter for suspicious TGS requests
  SuspiciousTGSFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref DirectoryLogGroup
      FilterPattern: '[time, event_id="4769", account, service, client, ticket_options, ticket_encryption, result!="0x0"]'
      MetricTransformations:
        - MetricName: SuspiciousTGSRequests
          MetricNamespace: Security/T1550003
          MetricValue: "1"

  # Step 2: Create SNS topic for alerts
  SecurityAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: Pass the Ticket Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 3: Alert on suspicious ticket patterns
  PassTheTicketAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1550003-PassTheTicket
      AlarmDescription: Suspicious Kerberos ticket activity detected
      MetricName: SuspiciousTGSRequests
      Namespace: Security/T1550003
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 5
      ComparisonOperator: GreaterThanThreshold
      AlarmActions:
        - !Ref SecurityAlertTopic

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref SecurityAlertTopic]
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: cloudwatch.amazonaws.com
            Action: sns:Publish
            Resource: !Ref SecurityAlertTopic""",
                terraform_template="""# Monitor AWS Managed Microsoft AD for Pass the Ticket attacks

variable "directory_log_group" {
  type        = string
  description = "CloudWatch log group for Managed AD security logs"
  default     = "/aws/directoryservice/d-*/security"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "pass_the_ticket_alerts" {
  name         = "pass-the-ticket-alerts"
  display_name = "Pass the Ticket Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.pass_the_ticket_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for suspicious TGS requests
resource "aws_cloudwatch_log_metric_filter" "suspicious_tgs" {
  name           = "suspicious-tgs-requests"
  log_group_name = var.directory_log_group
  pattern        = "[time, event_id=\"4769\", account, service, client, ticket_options, ticket_encryption, result!=\"0x0\"]"

  metric_transformation {
    name      = "SuspiciousTGSRequests"
    namespace = "Security/T1550003"
    value     = "1"
  }
}

# Step 3: Alert on suspicious ticket patterns
resource "aws_cloudwatch_metric_alarm" "pass_the_ticket" {
  alarm_name          = "T1550003-PassTheTicket"
  alarm_description   = "Suspicious Kerberos ticket activity detected"
  metric_name         = "SuspiciousTGSRequests"
  namespace           = "Security/T1550003"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 5
  comparison_operator = "GreaterThanThreshold"
  alarm_actions       = [aws_sns_topic.pass_the_ticket_alerts.arn]
}""",
                alert_severity="high",
                alert_title="Suspicious Kerberos Ticket Activity Detected",
                alert_description_template=(
                    "Suspicious Kerberos authentication patterns detected for account {account}. "
                    "Multiple service ticket requests without corresponding logon events. "
                    "Client IP: {client_ip}. This may indicate Pass the Ticket attack."
                ),
                investigation_steps=[
                    "Review Directory Service security logs for Event IDs 4768, 4769, 4770, and 4624",
                    "Identify if TGS requests (4769) exist without corresponding logon events (4624)",
                    "Check for unusual ticket encryption types (DES, RC4 when AES is standard)",
                    "Review the source IP addresses and verify they are expected for the account",
                    "Check for multiple service ticket requests in short time periods",
                    "Investigate if the account has been recently compromised or credentials dumped",
                    "Review CloudTrail for API activity from affected accounts",
                ],
                containment_actions=[
                    "Reset the affected user account password immediately",
                    "Revoke all active Kerberos tickets for the account",
                    "Review and reset the KRBTGT account password twice (with appropriate delays)",
                    "Enable MFA for the affected account if not already enabled",
                    "Audit all systems accessed using suspicious tickets",
                    "Review and restrict lateral movement paths",
                    "Implement privileged access workstation policies",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal ticket request patterns for service accounts; exclude known automated systems",
            detection_coverage="55% - detects anomalous ticket patterns in managed AD environments",
            evasion_considerations="Attackers may slow ticket usage to blend with normal authentication patterns",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$10-25 depending on directory size and log volume",
            prerequisites=[
                "AWS Managed Microsoft AD deployed",
                "Security event logging enabled and sent to CloudWatch Logs",
                "Windows Event IDs 4768, 4769, 4770, 4624 logged",
            ],
        ),
        # Strategy 2: Hybrid Cloud Authentication Anomalies
        DetectionStrategy(
            strategy_id="t1550003-hybrid-auth-anomaly",
            name="Detect Hybrid Cloud Authentication Anomalies",
            description=(
                "Monitor for authentication patterns indicating stolen tickets used to access "
                "cloud resources from on-premises AD, including impossible travel, unusual "
                "resource access, and authentication without MFA where required."
            ),
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "UnauthorizedAccess:IAMUser/AnomalousBehavior",
                    "CredentialAccess:IAMUser/AnomalousBehavior",
                    "InitialAccess:IAMUser/AnomalousBehavior",
                ],
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect hybrid cloud authentication anomalies

Parameters:
  AlertEmail:
    Type: String
    Description: Email for alerts

Resources:
  # Step 1: Enable GuardDuty for anomalous behaviour detection
  GuardDutyDetector:
    Type: AWS::GuardDuty::Detector
    Properties:
      Enable: true
      FindingPublishingFrequency: FIFTEEN_MINUTES

  # Step 2: Create SNS topic
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: Hybrid Auth Anomaly Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 3: Route anomalous authentication findings
  HybridAuthAnomalyRule:
    Type: AWS::Events::Rule
    Properties:
      Name: T1550003-HybridAuthAnomaly
      Description: Detect authentication anomalies in hybrid environments
      EventPattern:
        source: [aws.guardduty]
        detail:
          type:
            - prefix: "UnauthorizedAccess:IAMUser"
            - prefix: "CredentialAccess:IAMUser"
            - prefix: "InitialAccess:IAMUser"
      State: ENABLED
      Targets:
        - Id: AlertTopic
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
            Resource: !Ref AlertTopic""",
                terraform_template="""# Detect hybrid cloud authentication anomalies

variable "alert_email" {
  type = string
}

# Step 1: Enable GuardDuty for anomalous behaviour detection
resource "aws_guardduty_detector" "main" {
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"
}

# Step 2: Create SNS topic
resource "aws_sns_topic" "hybrid_auth_alerts" {
  name         = "hybrid-auth-anomaly-alerts"
  display_name = "Hybrid Auth Anomaly Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.hybrid_auth_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 3: Route anomalous authentication findings
resource "aws_cloudwatch_event_rule" "hybrid_auth_anomaly" {
  name        = "guardduty-hybrid-auth-anomaly"
  description = "Detect authentication anomalies in hybrid environments"
  event_pattern = jsonencode({
    source = ["aws.guardduty"]
    detail = {
      type = [
        { prefix = "UnauthorizedAccess:IAMUser" },
        { prefix = "CredentialAccess:IAMUser" },
        { prefix = "InitialAccess:IAMUser" }
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.hybrid_auth_anomaly.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.hybrid_auth_alerts.arn
}

resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.hybrid_auth_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.hybrid_auth_alerts.arn
    }]
  })
}""",
                alert_severity="high",
                alert_title="Hybrid Cloud Authentication Anomaly",
                alert_description_template=(
                    "Anomalous authentication detected for federated user {user}. "
                    "Finding: {finding_type}. Source IP: {source_ip}. "
                    "May indicate stolen Kerberos tickets used for cloud access."
                ),
                investigation_steps=[
                    "Review GuardDuty finding details for the federated user",
                    "Check if authentication originated from expected AD-federated source",
                    "Verify MFA was used if required by policy",
                    "Review geographic location of authentication",
                    "Check CloudTrail for all API activity from the federated session",
                    "Verify with on-premises AD logs for corresponding authentication events",
                    "Look for signs of credential dumping on user's workstation",
                ],
                containment_actions=[
                    "Terminate all active federated sessions for the affected user",
                    "Reset the user's AD password",
                    "Revoke all Kerberos tickets in AD",
                    "Review and revoke any AWS STS sessions",
                    "Enable MFA enforcement for federated access if not configured",
                    "Review trust relationship between AD and AWS",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal authentication patterns for federated users; consider travelling employees",
            detection_coverage="60% - detects behavioral anomalies in federated authentication",
            evasion_considerations="Attackers using VPNs in expected regions may evade detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$4 per million events analysed",
            prerequisites=["GuardDuty enabled", "SAML or AD federation configured"],
        ),
        # Strategy 3: Domain Controller API Access Monitoring
        DetectionStrategy(
            strategy_id="t1550003-dc-api-monitoring",
            name="Monitor Domain Controller and Directory Service API Access",
            description=(
                "Detect unusual API calls to directory services that may indicate ticket "
                "manipulation or Golden Ticket creation, including KRBTGT account access, "
                "DCSync operations, and unusual replication requests."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.arn, eventName, requestParameters, sourceIPAddress
| filter eventSource = "ds.amazonaws.com"
| filter eventName in ["ResetUserPassword", "DescribeDirectories", "GetDirectoryLimits", "VerifyTrust"]
  or requestParameters.userName like /krbtgt|administrator/
| stats count(*) as api_count by userIdentity.arn, eventName, sourceIPAddress, bin(10m)
| filter api_count > 3
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Monitor Directory Service API for ticket manipulation

Parameters:
  CloudTrailLogGroup:
    Type: String
    Description: CloudTrail log group name
  SNSTopicArn:
    Type: String
    Description: SNS topic for alerts

Resources:
  # Step 1: Monitor KRBTGT account access
  KRBTGTAccessFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventSource = "ds.amazonaws.com" && $.requestParameters.userName = "*krbtgt*" }'
      MetricTransformations:
        - MetricName: KRBTGTAccountAccess
          MetricNamespace: Security/T1550003
          MetricValue: "1"

  # Step 2: Monitor directory password resets
  DirectoryPasswordResetFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventSource = "ds.amazonaws.com" && $.eventName = "ResetUserPassword" }'
      MetricTransformations:
        - MetricName: DirectoryPasswordResets
          MetricNamespace: Security/T1550003
          MetricValue: "1"

  # Step 3: Alert on suspicious directory operations
  SuspiciousDirectoryOpsAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1550003-SuspiciousDirectoryOps
      AlarmDescription: Suspicious directory service operations detected
      MetricName: KRBTGTAccountAccess
      Namespace: Security/T1550003
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 1
      ComparisonOperator: GreaterThanOrEqualToThreshold
      AlarmActions:
        - !Ref SNSTopicArn""",
                terraform_template="""# Monitor Directory Service API for ticket manipulation

variable "cloudtrail_log_group" {
  type = string
}

variable "alert_email" {
  type = string
}

resource "aws_sns_topic" "alerts" {
  name = "directory-api-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 1: Monitor KRBTGT account access
resource "aws_cloudwatch_log_metric_filter" "krbtgt_access" {
  name           = "krbtgt-account-access"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventSource = \"ds.amazonaws.com\" && $.requestParameters.userName = \"*krbtgt*\" }"

  metric_transformation {
    name      = "KRBTGTAccountAccess"
    namespace = "Security/T1550003"
    value     = "1"
  }
}

# Step 2: Monitor directory password resets
resource "aws_cloudwatch_log_metric_filter" "password_resets" {
  name           = "directory-password-resets"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventSource = \"ds.amazonaws.com\" && $.eventName = \"ResetUserPassword\" }"

  metric_transformation {
    name      = "DirectoryPasswordResets"
    namespace = "Security/T1550003"
    value     = "1"
  }
}

# Step 3: Alert on suspicious directory operations
resource "aws_cloudwatch_metric_alarm" "suspicious_directory_ops" {
  alarm_name          = "T1550003-SuspiciousDirectoryOps"
  alarm_description   = "Suspicious directory service operations detected"
  metric_name         = "KRBTGTAccountAccess"
  namespace           = "Security/T1550003"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="critical",
                alert_title="Suspicious Directory Service Operation",
                alert_description_template=(
                    "Suspicious directory operation detected. Event: {event_name}. "
                    "User: {user_arn}. Target account: {target_account}. "
                    "Source IP: {source_ip}. May indicate Golden Ticket preparation."
                ),
                investigation_steps=[
                    "Verify if the API call was authorised and expected",
                    "Check if KRBTGT account password was accessed or reset",
                    "Review CloudTrail for all actions by the principal in last 24 hours",
                    "Verify the source IP is expected for this type of operation",
                    "Check for signs of DCSync or credential dumping on domain controllers",
                    "Review AD security event logs for corresponding events",
                    "Audit who has permissions to reset directory passwords",
                ],
                containment_actions=[
                    "If unauthorised, immediately rotate KRBTGT password twice with delays",
                    "Revoke AWS IAM credentials used to make the API call",
                    "Review and restrict IAM policies for Directory Service access",
                    "Enable MFA requirement for sensitive directory operations",
                    "Audit all password reset operations in the last 30 days",
                    "Implement SCPs to restrict directory modifications to specific roles",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Create exceptions for authorised directory management automation",
            detection_coverage="70% - detects API-based ticket manipulation attempts",
            evasion_considerations="On-premises ticket forging may not generate AWS API calls",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=[
                "CloudTrail enabled",
                "AWS Managed Microsoft AD or AD Connector",
            ],
        ),
        # Strategy 4: GCP Identity-Aware Proxy Anomalies
        DetectionStrategy(
            strategy_id="t1550003-gcp-iap-anomaly",
            name="GCP: Detect Identity-Aware Proxy Authentication Anomalies",
            description=(
                "Monitor GCP Identity-Aware Proxy for authentication anomalies that may "
                "indicate stolen authentication tokens or tickets being used to access "
                "cloud resources in hybrid environments."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="cloud_run_revision" OR resource.type="app_engine_application"
protoPayload.authenticationInfo.principalEmail!=""
(protoPayload.response.status="UNAUTHENTICATED"
OR protoPayload.response.status="PERMISSION_DENIED"
OR jsonPayload.message=~"authentication.*failed|ticket.*invalid|token.*expired")""",
                gcp_terraform_template="""# GCP: Detect IAP authentication anomalies

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
  display_name = "IAP Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log-based metric for authentication failures
resource "google_logging_metric" "iap_auth_anomalies" {
  project = var.project_id
  name    = "iap-authentication-anomalies"
  filter  = <<-EOT
    resource.type="cloud_run_revision" OR resource.type="app_engine_application"
    protoPayload.authenticationInfo.principalEmail!=""
    (protoPayload.response.status="UNAUTHENTICATED"
    OR protoPayload.response.status="PERMISSION_DENIED"
    OR jsonPayload.message=~"authentication.*failed|ticket.*invalid|token.*expired")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "principal_email"
      value_type  = "STRING"
      description = "User with authentication anomaly"
    }
    labels {
      key         = "source_ip"
      value_type  = "STRING"
      description = "Source IP of authentication attempt"
    }
  }

  label_extractors = {
    principal_email = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
    source_ip       = "EXTRACT(protoPayload.requestMetadata.callerIp)"
  }
}

# Step 3: Create alert policy
resource "google_monitoring_alert_policy" "iap_auth_anomalies" {
  project      = var.project_id
  display_name = "T1550.003: IAP Authentication Anomalies"
  combiner     = "OR"
  conditions {
    display_name = "Authentication anomalies detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.iap_auth_anomalies.name}\" resource.type=\"cloud_run_revision\""
      duration        = "60s"
      comparison      = "COMPARISON_GT"
      threshold_value = 5
      aggregations {
        alignment_period     = "60s"
        per_series_aligner   = "ALIGN_RATE"
        cross_series_reducer = "REDUCE_SUM"
        group_by_fields      = ["metric.label.principal_email"]
      }
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
  alert_strategy {
    auto_close = "1800s"
  }
  documentation {
    content   = "Multiple authentication anomalies detected. Investigate for stolen tickets or tokens."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="high",
                alert_title="GCP: IAP Authentication Anomaly",
                alert_description_template=(
                    "Multiple authentication anomalies detected for user {principal_email}. "
                    "Source IP: {source_ip}. Status: {status}. "
                    "May indicate stolen authentication material."
                ),
                investigation_steps=[
                    "Review Cloud Logging for detailed authentication failure messages",
                    "Verify the user's identity and expected authentication sources",
                    "Check if the source IP is from an expected location",
                    "Review recent successful authentications for the user",
                    "Look for patterns of authentication attempts across multiple services",
                    "Check if the user reported any suspicious activity",
                    "Review workspace or Cloud Identity logs for account compromise indicators",
                ],
                containment_actions=[
                    "Suspend the affected user account temporarily",
                    "Force password reset and revoke all active sessions",
                    "Review and revoke any OAuth tokens for the user",
                    "Enable 2FA if not already configured",
                    "Review IAM bindings for the affected user",
                    "Audit resources accessed by the user in the last 24 hours",
                    "Implement context-aware access policies with additional verification",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal authentication patterns; account for mobile users and VPNs",
            detection_coverage="50% - detects authentication anomalies in cloud-based resources",
            evasion_considerations="Attackers with valid stolen tokens may not trigger failures",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1.5 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["Identity-Aware Proxy enabled", "Cloud Logging API enabled"],
        ),
        # Strategy 5: Windows EC2 Instance Authentication Monitoring
        DetectionStrategy(
            strategy_id="t1550003-ec2-windows-auth",
            name="Monitor Windows EC2 Instances for Kerberos Ticket Injection",
            description=(
                "Use CloudWatch Logs to detect Kerberos ticket injection on Windows EC2 instances, "
                "including Mimikatz activity, unusual LSASS access, and suspicious ticket operations."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query=r"""fields @timestamp, @message, instanceId, eventID, process, commandLine
| filter eventID in [4768, 4769, 4770] or @message like /mimikatz|kerberos::ptt|sekurlsa::tickets|Invoke-Mimikatz|lsadump/
| parse @message /EventID=(?<event_id>\d+).*Account:\s+(?<account>[^\s]+).*Service:\s+(?<service>[^\s]+)/
| stats count(*) as ticket_events, count_distinct(service) as unique_services by instanceId, account, bin(5m)
| filter ticket_events > 10 or unique_services > 5
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Monitor Windows EC2 for Kerberos ticket injection

Parameters:
  WindowsLogGroup:
    Type: String
    Description: CloudWatch log group for Windows instance logs
    Default: /aws/ec2/windows/security
  SNSTopicArn:
    Type: String

Resources:
  # Step 1: Detect Mimikatz or ticket tools
  TicketToolFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref WindowsLogGroup
      FilterPattern: '[time, instance, process="*mimikatz*" || process="*kerberos::ptt*" || process="*sekurlsa::tickets*"]'
      MetricTransformations:
        - MetricName: KerberosTicketTools
          MetricNamespace: Security/T1550003
          MetricValue: "1"

  # Step 2: Monitor excessive ticket operations
  ExcessiveTicketOpsFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref WindowsLogGroup
      FilterPattern: '[time, event_id="4769", account, service]'
      MetricTransformations:
        - MetricName: ServiceTicketRequests
          MetricNamespace: Security/T1550003
          MetricValue: "1"

  # Step 3: Alert on ticket injection indicators
  TicketInjectionAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1550003-TicketInjection
      AlarmDescription: Kerberos ticket injection detected on EC2 instance
      MetricName: KerberosTicketTools
      Namespace: Security/T1550003
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 1
      ComparisonOperator: GreaterThanOrEqualToThreshold
      AlarmActions:
        - !Ref SNSTopicArn""",
                terraform_template="""# Monitor Windows EC2 for Kerberos ticket injection

variable "windows_log_group" {
  type    = string
  default = "/aws/ec2/windows/security"
}

variable "alert_email" {
  type = string
}

resource "aws_sns_topic" "alerts" {
  name = "kerberos-ticket-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 1: Detect Mimikatz or ticket tools
resource "aws_cloudwatch_log_metric_filter" "ticket_tools" {
  name           = "kerberos-ticket-tools"
  log_group_name = var.windows_log_group
  pattern        = "[time, instance, process=\"*mimikatz*\" || process=\"*kerberos::ptt*\" || process=\"*sekurlsa::tickets*\"]"

  metric_transformation {
    name      = "KerberosTicketTools"
    namespace = "Security/T1550003"
    value     = "1"
  }
}

# Step 2: Monitor excessive ticket operations
resource "aws_cloudwatch_log_metric_filter" "ticket_ops" {
  name           = "service-ticket-requests"
  log_group_name = var.windows_log_group
  pattern        = "[time, event_id=\"4769\", account, service]"

  metric_transformation {
    name      = "ServiceTicketRequests"
    namespace = "Security/T1550003"
    value     = "1"
  }
}

# Step 3: Alert on ticket injection indicators
resource "aws_cloudwatch_metric_alarm" "ticket_injection" {
  alarm_name          = "T1550003-TicketInjection"
  alarm_description   = "Kerberos ticket injection detected on EC2 instance"
  metric_name         = "KerberosTicketTools"
  namespace           = "Security/T1550003"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="critical",
                alert_title="Kerberos Ticket Injection Detected",
                alert_description_template=(
                    "Kerberos ticket injection activity detected on instance {instance_id}. "
                    "Process: {process}. Account: {account}. "
                    "Immediate investigation required for Pass the Ticket attack."
                ),
                investigation_steps=[
                    "Review Windows Security Event Logs for Event IDs 4768, 4769, 4770",
                    "Check for Mimikatz or other credential dumping tools on the instance",
                    "Review process execution logs for suspicious PowerShell or command-line activity",
                    "Identify which accounts had tickets injected",
                    "Check for lateral movement attempts from the instance",
                    "Review network connections for communication with domain controllers",
                    "Examine CloudTrail for AWS API calls made using instance credentials",
                ],
                containment_actions=[
                    "Isolate the instance from the network immediately",
                    "Create a memory dump and disk snapshot for forensics",
                    "Reset passwords for all accounts that had activity on the instance",
                    "Revoke all Kerberos tickets for affected accounts in Active Directory",
                    "Terminate the instance if compromise is confirmed",
                    "Review and reset KRBTGT account password if Golden Ticket suspected",
                    "Audit all domain-joined instances for similar activity",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist authorised security testing; exclude known administrative tools with approval",
            detection_coverage="80% - detects known ticket injection techniques and tools",
            evasion_considerations="Custom or obfuscated tools may evade signature detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$10-30 depending on instance count and log volume",
            prerequisites=[
                "Windows EC2 instances domain-joined",
                "CloudWatch Logs Agent configured to send Security event logs",
                "Windows Event IDs 4768, 4769, 4770 configured for logging",
            ],
        ),
    ],
    recommended_order=[
        "t1550003-ec2-windows-auth",
        "t1550003-aws-mad-monitoring",
        "t1550003-dc-api-monitoring",
        "t1550003-hybrid-auth-anomaly",
        "t1550003-gcp-iap-anomaly",
    ],
    total_effort_hours=8.0,
    coverage_improvement="+25% improvement for Lateral Movement and Defence Evasion tactics",
)
