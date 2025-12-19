"""
T1550.002 - Use Alternate Authentication Material: Pass the Hash

Adversaries use stolen NTLM password hashes to authenticate without the cleartext password,
enabling lateral movement across Windows environments.
Used by APT1, APT28, APT32, APT41, Wizard Spider for lateral movement.
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
    technique_id="T1550.002",
    technique_name="Use Alternate Authentication Material: Pass the Hash",
    tactic_ids=["TA0005", "TA0008"],
    mitre_url="https://attack.mitre.org/techniques/T1550/002/",

    threat_context=ThreatContext(
        description=(
            "Adversaries leverage stolen NTLM password hashes to authenticate to remote systems "
            "without needing the cleartext password. This technique bypasses standard authentication "
            "by using captured hashes directly in the authentication process. In cloud environments, "
            "this primarily affects Windows-based EC2 instances, hybrid Active Directory deployments, "
            "and organisations with on-premises AD integrated with cloud services. A variant called "
            "'overpass the hash' converts the password hash into Kerberos tickets for Pass the Ticket attacks."
        ),
        attacker_goal="Achieve lateral movement across Windows systems using stolen password hashes",
        why_technique=[
            "Bypasses password-based authentication controls",
            "No cleartext password required",
            "Enables lateral movement to multiple systems",
            "Works even after password change in some cases",
            "Difficult to distinguish from legitimate authentication",
            "Effective against systems with shared local administrator passwords",
            "Can be combined with credential dumping for broad access"
        ],
        known_threat_actors=[
            "APT1", "APT28", "APT32", "APT41", "Wizard Spider", "Lazarus Group",
            "Carbanak", "FIN6", "FIN7", "Turla", "OilRig", "Threat Group-3390"
        ],
        recent_campaigns=[
            Campaign(
                name="APT41 Global Intrusion Campaign",
                year=2023,
                description="Used pass-the-hash techniques to move laterally across Windows domains in cloud-connected environments",
                reference_url="https://attack.mitre.org/groups/G0096/"
            ),
            Campaign(
                name="Wizard Spider Ransomware Operations",
                year=2022,
                description="Leveraged stolen NTLM hashes to deploy ransomware across Windows networks including hybrid cloud deployments",
                reference_url="https://attack.mitre.org/groups/G0102/"
            ),
            Campaign(
                name="APT28 Credential Harvesting",
                year=2021,
                description="Employed pass-the-hash after dumping credentials from compromised domain controllers",
                reference_url="https://attack.mitre.org/groups/G0007/"
            )
        ],
        prevalence="common",
        trend="stable",
        severity_score=8,
        severity_reasoning=(
            "Pass the Hash is a critical lateral movement technique in Windows environments. "
            "It enables attackers to move laterally across networks after initial compromise "
            "without triggering password-based alerts. In hybrid cloud environments, this can "
            "bridge on-premises and cloud resources, significantly expanding the attack surface. "
            "Particularly dangerous when combined with shared local administrator accounts."
        ),
        business_impact=[
            "Lateral movement to sensitive Windows systems",
            "Privilege escalation via administrator hash reuse",
            "Ransomware deployment across multiple systems",
            "Data exfiltration from connected file servers and databases",
            "Compromise of hybrid cloud identity infrastructure",
            "Persistent access through multiple compromised accounts"
        ],
        typical_attack_phase="lateral_movement",
        often_precedes=["T1021.002", "T1021.001", "T1047", "T1570"],
        often_follows=["T1003.001", "T1003.002", "T1003.003", "T1078"]
    ),

    detection_strategies=[
        # Strategy 1: NTLM Authentication Monitoring
        DetectionStrategy(
            strategy_id="t1550002-ntlm-lateral",
            name="AWS GuardDuty Windows Authentication Monitoring",
            description=(
                "Monitor for suspicious NTLM authentication patterns on Windows EC2 instances, "
                "including logon type 3 (network) authentications without corresponding domain "
                "logon events, and authentication from unexpected source systems."
            ),
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "UnauthorizedAccess:EC2/RDPBruteForce",
                    "UnauthorizedAccess:EC2/SSHBruteForce",
                    "Behavior:EC2/NetworkPortUnusual",
                    "CredentialAccess:IAMUser/AnomalousBehavior"
                ],
                cloudformation_template='''AWSTemplateFormatVersion: '2010-09-09'
Description: GuardDuty monitoring for Pass the Hash indicators

Parameters:
  AlertEmail:
    Type: String
    Description: Email address for security alerts

Resources:
  # Step 1: Enable GuardDuty for anomaly detection
  GuardDutyDetector:
    Type: AWS::GuardDuty::Detector
    Properties:
      Enable: true
      FindingPublishingFrequency: FIFTEEN_MINUTES

  # Step 2: Create SNS topic for alerts
  SecurityAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: Pass the Hash Detection Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 3: Route suspicious authentication findings to SNS
  SuspiciousAuthRule:
    Type: AWS::Events::Rule
    Properties:
      Name: T1550-002-PassTheHash
      Description: Detect suspicious Windows authentication patterns
      EventPattern:
        source: [aws.guardduty]
        detail:
          type:
            - prefix: "UnauthorizedAccess:EC2"
            - prefix: "CredentialAccess"
            - prefix: "Behavior:EC2"
      State: ENABLED
      Targets:
        - Id: SecurityAlerts
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
            Resource: !Ref SecurityAlertTopic''',
                terraform_template='''# GuardDuty monitoring for Pass the Hash indicators

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: Enable GuardDuty for anomaly detection
resource "aws_guardduty_detector" "main" {
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"
}

# Step 2: Create SNS topic for alerts
resource "aws_sns_topic" "pth_alerts" {
  name         = "pass-the-hash-alerts"
  display_name = "Pass the Hash Detection Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.pth_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 3: Route suspicious authentication findings to SNS
resource "aws_cloudwatch_event_rule" "suspicious_auth" {
  name        = "T1550-002-PassTheHash"
  description = "Detect suspicious Windows authentication patterns"

  event_pattern = jsonencode({
    source = ["aws.guardduty"]
    detail = {
      type = [
        { prefix = "UnauthorizedAccess:EC2" },
        { prefix = "CredentialAccess" },
        { prefix = "Behavior:EC2" }
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.suspicious_auth.name
  arn  = aws_sns_topic.pth_alerts.arn
}

resource "aws_sns_topic_policy" "allow_events" {
  arn = aws_sns_topic.pth_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.pth_alerts.arn
    }]
  })
}''',
                alert_severity="high",
                alert_title="Suspicious Windows Authentication Pattern Detected",
                alert_description_template=(
                    "Potential Pass the Hash activity detected on instance {instance_id}. "
                    "Unusual authentication pattern observed from {source_ip}. "
                    "Finding type: {finding_type}."
                ),
                investigation_steps=[
                    "Review Windows Security Event logs (Event ID 4624) for logon type 3 without domain logon",
                    "Check for NTLM authentications (Event ID 4776) from unexpected sources",
                    "Identify all systems accessed by the suspicious account within the timeframe",
                    "Review recent credential dumping indicators (Event ID 4672, 4688 for LSASS access)",
                    "Examine network traffic for SMB/RPC connections between systems",
                    "Check for overpass-the-hash via Kerberos ticket requests (Event ID 4768, 4769)",
                    "Review user's normal access patterns and compare with current activity"
                ],
                containment_actions=[
                    "Immediately isolate affected Windows instances from the network",
                    "Reset passwords for all potentially compromised accounts",
                    "Disable affected user accounts pending investigation",
                    "Enable Restricted Admin mode for RDP if not already enabled",
                    "Review and rotate local administrator passwords across all systems",
                    "Enable NTLM auditing and restrict NTLM authentication where possible",
                    "Force Kerberos authentication for lateral movement"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "Exclude known service accounts that authenticate via NTLM; "
                "whitelist legitimate administrative workstations; "
                "baseline normal lateral movement patterns for system administrators"
            ),
            detection_coverage="60% - catches anomalous authentication patterns but may miss sophisticated attacks",
            evasion_considerations=(
                "Attackers may use legitimate administrator workstations; "
                "slow lateral movement may evade rate-based detection; "
                "Kerberos-based overpass-the-hash may bypass NTLM monitoring"
            ),
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="£10-30 depending on instance count",
            prerequisites=["GuardDuty enabled", "Windows EC2 instances configured"]
        ),

        # Strategy 2: CloudWatch Logs Analysis for Windows Events
        DetectionStrategy(
            strategy_id="t1550002-cloudwatch-windows",
            name="CloudWatch Windows Event Log Analysis",
            description=(
                "Analyse Windows Security Event logs forwarded to CloudWatch for Pass the Hash "
                "indicators including NTLM LogonType 3 without corresponding domain authentication, "
                "and logon sessions created without password entry."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query='''fields @timestamp, EventID, LogonType, AuthenticationPackage,
       WorkstationName, SourceNetworkAddress, TargetUserName
| filter EventID = 4624 and LogonType = 3 and AuthenticationPackage = "NTLM"
| stats count(*) as ntlm_logons,
        count_distinct(SourceNetworkAddress) as unique_sources,
        count_distinct(WorkstationName) as unique_workstations
  by TargetUserName, bin(15m)
| filter ntlm_logons > 5 or unique_sources > 3
| sort @timestamp desc''',
                cloudformation_template='''AWSTemplateFormatVersion: '2010-09-09'
Description: CloudWatch analysis for Pass the Hash detection

Parameters:
  WindowsLogGroup:
    Type: String
    Description: CloudWatch log group containing Windows Security logs
  AlertEmail:
    Type: String
    Description: Email for alerts

Resources:
  # Step 1: Create metric filter for suspicious NTLM authentication
  NTLMAuthMetricFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref WindowsLogGroup
      FilterPattern: '[EventID=4624, LogonType=3, AuthPackage=NTLM]'
      MetricTransformations:
        - MetricName: SuspiciousNTLMAuth
          MetricNamespace: Security/T1550
          MetricValue: 1
          DefaultValue: 0

  # Step 2: Create SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 3: Create alarm for excessive NTLM authentication
  NTLMAuthAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1550-002-ExcessiveNTLM
      AlarmDescription: Multiple NTLM authentications detected - possible PtH
      MetricName: SuspiciousNTLMAuth
      Namespace: Security/T1550
      Statistic: Sum
      Period: 900
      EvaluationPeriods: 1
      Threshold: 10
      ComparisonOperator: GreaterThanThreshold
      AlarmActions:
        - !Ref AlertTopic''',
                terraform_template='''# CloudWatch analysis for Pass the Hash detection

variable "windows_log_group" {
  type        = string
  description = "CloudWatch log group containing Windows Security logs"
}

variable "alert_email" {
  type = string
}

# Step 1: Create metric filter for suspicious NTLM authentication
resource "aws_cloudwatch_log_metric_filter" "ntlm_auth" {
  name           = "suspicious-ntlm-authentication"
  log_group_name = var.windows_log_group
  pattern        = "[EventID=4624, LogonType=3, AuthPackage=NTLM]"

  metric_transformation {
    name      = "SuspiciousNTLMAuth"
    namespace = "Security/T1550"
    value     = "1"
    default_value = 0
  }
}

# Step 2: Create SNS topic for alerts
resource "aws_sns_topic" "ntlm_alerts" {
  name = "ntlm-pth-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.ntlm_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 3: Create alarm for excessive NTLM authentication
resource "aws_cloudwatch_metric_alarm" "excessive_ntlm" {
  alarm_name          = "T1550-002-ExcessiveNTLM"
  alarm_description   = "Multiple NTLM authentications detected - possible PtH"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "SuspiciousNTLMAuth"
  namespace           = "Security/T1550"
  period              = 900
  statistic           = "Sum"
  threshold           = 10
  alarm_actions       = [aws_sns_topic.ntlm_alerts.arn]
}''',
                alert_severity="high",
                alert_title="Excessive NTLM Authentication Activity",
                alert_description_template=(
                    "User {username} has {ntlm_logons} NTLM network logons from {unique_sources} "
                    "different sources in 15 minutes. This may indicate Pass the Hash activity."
                ),
                investigation_steps=[
                    "Query CloudWatch Logs for Event ID 4624 (successful logon) with LogonType 3 and NTLM",
                    "Check for corresponding Event ID 4776 (NTLM authentication) entries",
                    "Look for Event ID 4672 (special privileges assigned) immediately after logon",
                    "Review source workstation names for anomalies or unknown systems",
                    "Check if source IP addresses match expected administrative workstations",
                    "Investigate Event ID 4688 (process creation) for suspicious tools (Mimikatz, PSExec)",
                    "Review user's authentication history for baseline comparison"
                ],
                containment_actions=[
                    "Isolate source and target systems from network",
                    "Force password reset for affected accounts",
                    "Clear cached credentials on all potentially compromised systems",
                    "Review and update local administrator password policy",
                    "Enable Protected Users group membership for sensitive accounts",
                    "Deploy Windows Defender Credential Guard if supported"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "Establish baseline for service accounts using NTLM; "
                "exclude scheduled tasks and automated processes; "
                "adjust threshold based on environment size and normal activity"
            ),
            detection_coverage="70% - detects NTLM-based PtH but may miss Kerberos overpass-the-hash",
            evasion_considerations=(
                "Attackers using overpass-the-hash (Kerberos) will evade NTLM-focused detection; "
                "slow-and-low attacks below threshold may go unnoticed; "
                "legitimate admin activity patterns may be mimicked"
            ),
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="£15-50 depending on log volume",
            prerequisites=[
                "CloudWatch Agent installed on Windows EC2 instances",
                "Windows Security Event logs forwarded to CloudWatch",
                "Event IDs 4624, 4776, 4672, 4688 enabled in audit policy"
            ]
        ),

        # Strategy 3: GCP Windows VM Authentication Monitoring
        DetectionStrategy(
            strategy_id="t1550002-gcp-windows",
            name="GCP Cloud Logging Windows Authentication Analysis",
            description=(
                "Monitor Windows GCE instances for Pass the Hash indicators through Cloud Logging "
                "analysis of Windows Event logs, focusing on NTLM authentication patterns and "
                "lateral movement indicators."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gce_instance"
jsonPayload.EventID="4624"
jsonPayload.LogonType="3"
jsonPayload.AuthenticationPackageName="NTLM"''',
                gcp_terraform_template='''# GCP Cloud Logging for Pass the Hash detection

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type = string
}

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Pass the Hash Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log-based metric for NTLM authentication
resource "google_logging_metric" "ntlm_logons" {
  name   = "suspicious-ntlm-logons"
  filter = <<-EOT
    resource.type="gce_instance"
    jsonPayload.EventID="4624"
    jsonPayload.LogonType="3"
    jsonPayload.AuthenticationPackageName="NTLM"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "instance_id"
      value_type  = "STRING"
      description = "GCE instance ID"
    }
  }

  label_extractors = {
    "instance_id" = "EXTRACT(resource.labels.instance_id)"
  }
}

# Step 3: Create alert policy for excessive NTLM authentication
resource "google_monitoring_alert_policy" "ntlm_alert" {
  display_name = "T1550.002 - Pass the Hash Detection"
  combiner     = "OR"

  conditions {
    display_name = "Excessive NTLM network logons"

    condition_threshold {
      filter          = "resource.type = \"gce_instance\" AND metric.type = \"logging.googleapis.com/user/${google_logging_metric.ntlm_logons.name}\""
      duration        = "900s"
      comparison      = "COMPARISON_GT"
      threshold_value = 10

      aggregations {
        alignment_period   = "900s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "86400s"
  }

  documentation {
    content = <<-EOT
      Potential Pass the Hash attack detected.

      Multiple NTLM network logons detected which may indicate use of stolen password hashes.

      Investigate:
      - Review Windows Security Event logs for Event IDs 4624, 4776
      - Check for credential dumping indicators
      - Verify source systems and user accounts involved

      Respond:
      - Isolate affected instances
      - Reset compromised account passwords
      - Review lateral movement paths
    EOT
  }
}''',
                alert_severity="high",
                alert_title="GCP: Suspicious NTLM Authentication Pattern",
                alert_description_template=(
                    "Excessive NTLM network logons detected on instance {instance_id}. "
                    "This may indicate Pass the Hash lateral movement activity."
                ),
                investigation_steps=[
                    "Access Cloud Logging and filter for Windows Event ID 4624 with LogonType 3",
                    "Review NTLM authentication events (Event ID 4776) for the timeframe",
                    "Check VPC Flow Logs for SMB/RPC connections between instances",
                    "Identify all instances accessed by the suspicious user account",
                    "Review Cloud Audit Logs for any privilege escalation attempts",
                    "Check for credential dumping indicators in earlier timeframes",
                    "Compare with baseline authentication patterns for the user"
                ],
                containment_actions=[
                    "Use GCP Console to stop affected GCE instances",
                    "Create snapshots before remediation for forensic analysis",
                    "Reset passwords for compromised accounts in Cloud Identity/AD",
                    "Review and update firewall rules to restrict lateral movement",
                    "Enable VPC Service Controls to limit inter-resource access",
                    "Deploy security patches and enable Windows Defender Credential Guard"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "Baseline normal NTLM usage for legacy applications; "
                "exclude service accounts with expected NTLM authentication; "
                "adjust thresholds based on environment authentication patterns"
            ),
            detection_coverage="65% - effective for NTLM-based attacks on GCP Windows VMs",
            evasion_considerations=(
                "Kerberos-based overpass-the-hash will evade NTLM-focused detection; "
                "attackers may throttle authentication attempts to stay below thresholds; "
                "use of legitimate admin credentials may blend with normal activity"
            ),
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="£10-40 depending on log ingestion volume",
            prerequisites=[
                "Windows GCE instances with logging agent installed",
                "Windows Security Event logs forwarded to Cloud Logging",
                "Appropriate IAM permissions to create logging metrics and alerts"
            ]
        )
    ],

    recommended_order=[
        "t1550002-ntlm-lateral",
        "t1550002-cloudwatch-windows",
        "t1550002-gcp-windows"
    ],
    total_effort_hours=6.0,
    coverage_improvement="+15% improvement for Defence Evasion and Lateral Movement tactics in Windows-based cloud environments"
)
