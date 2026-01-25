"""
T1133 - External Remote Services

Adversaries exploit external-facing remote services like VPNs, Citrix, RDP, and SSH
to gain initial access or maintain persistence. Includes exposed container APIs.
Used by APT29, Scattered Spider, Wizard Spider, TeamTNT, FIN5.
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
    technique_id="T1133",
    technique_name="External Remote Services",
    tactic_ids=["TA0001", "TA0003"],  # Initial Access, Persistence
    mitre_url="https://attack.mitre.org/techniques/T1133/",
    threat_context=ThreatContext(
        description=(
            "Adversaries leverage external-facing remote services like VPNs, Citrix, "
            "RDP, and SSH to gain initial access or maintain persistence. This includes "
            "exploiting exposed container APIs (Docker, Kubernetes) and establishing "
            "Tor hidden services for backdoor access."
        ),
        attacker_goal="Gain initial access or persistence via external remote services using compromised credentials",
        why_technique=[
            "Appears as legitimate remote access",
            "Bypasses perimeter security",
            "Enables persistent access",
            "Container APIs often exposed",
            "Difficult to distinguish from normal use",
            "Multiple protocols available (VPN, RDP, SSH)",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "Provides initial access and persistence using legitimate infrastructure. "
            "Difficult to detect as it mimics normal remote access patterns. Container "
            "API exposure is increasingly targeted."
        ),
        business_impact=[
            "Unauthorised network access",
            "Persistent backdoor access",
            "Lateral movement enabler",
            "Container compromise",
            "Credential theft risk",
            "Compliance violations",
        ],
        typical_attack_phase="initial_access",
        often_precedes=["T1078.004", "T1552.005", "T1021.007", "T1098"],
        often_follows=["T1110", "T1078"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1133-aws-vpn-unusual",
            name="AWS VPN Unusual Access Detection",
            description="Detect unusual VPN connection patterns and anomalous authentication.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.principalId, sourceIPAddress, userAgent, eventName
| filter eventSource = "signin.amazonaws.com"
| filter eventName = "ConsoleLogin"
| stats count(*) as login_count by sourceIPAddress, userIdentity.principalId, bin(1h)
| filter login_count > 1
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect unusual VPN and remote access patterns

Parameters:
  CloudTrailLogGroup:
    Type: String
    Description: CloudTrail log group name
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: VPN Access Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  UnusualVPNAccessFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventSource = "signin.amazonaws.com" && $.eventName = "ConsoleLogin" }'
      MetricTransformations:
        - MetricName: VPNAccessAttempts
          MetricNamespace: Security
          MetricValue: "1"

  UnusualVPNAccessAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: UnusualVPNAccess
      AlarmDescription: Detects unusual VPN access patterns
      MetricName: VPNAccessAttempts
      Namespace: Security
      Statistic: Sum
      Period: 300
      Threshold: 10
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref AlertTopic]
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Sid: AllowCloudWatchAlarms
            Effect: Allow
            Principal:
              Service: cloudwatch.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId""",
                terraform_template="""# Detect unusual VPN and remote access patterns

variable "cloudtrail_log_group" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name         = "vpn-access-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "VPN Access Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "unusual_vpn" {
  name           = "unusual-vpn-access"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventSource = \"signin.amazonaws.com\" && $.eventName = \"ConsoleLogin\" }"

  metric_transformation {
    name      = "VPNAccessAttempts"
    namespace = "Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "vpn_access" {
  alarm_name          = "UnusualVPNAccess"
  alarm_description   = "Detects unusual VPN access patterns"
  metric_name         = "VPNAccessAttempts"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 10
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.alerts.arn]
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "alerts" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchAlarms"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="Unusual VPN/Remote Access Detected",
                alert_description_template="Multiple VPN access attempts from {sourceIPAddress} for user {userIdentity.principalId}.",
                investigation_steps=[
                    "Review source IP geolocation and reputation",
                    "Check if access is from expected location",
                    "Review user agent for anomalies",
                    "Check for subsequent lateral movement",
                    "Review authentication logs for failed attempts",
                    "Verify user legitimacy and account status",
                ],
                containment_actions=[
                    "Revoke active sessions for compromised users",
                    "Block suspicious source IPs at security group level",
                    "Rotate compromised credentials immediately",
                    "Enable MFA if not already enabled",
                    "Review and update VPN access policies",
                    "Check for persistence mechanisms",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal remote access patterns per user and location. Filter known remote work locations.",
            detection_coverage="70% - catches unusual access patterns",
            evasion_considerations="Attackers using legitimate user patterns or expected locations may evade",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["CloudTrail enabled and logging to CloudWatch"],
        ),
        DetectionStrategy(
            strategy_id="t1133-aws-ec2-ssh-rdp",
            name="AWS EC2 SSH/RDP Access Detection",
            description="Detect external SSH and RDP connections to EC2 instances.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="vpc_flow_logs",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, srcaddr, dstaddr, dstport, action
| filter dstport in [22, 3389]
| filter action = "ACCEPT"
| stats count(*) as connection_count by srcaddr, dstport, bin(1h)
| filter connection_count > 5
| sort connection_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect external SSH/RDP connections

Parameters:
  VPCFlowLogsGroup:
    Type: String
    Description: VPC Flow Logs CloudWatch log group
  AlertEmail:
    Type: String

Resources:
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  SSHRDPFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref VPCFlowLogsGroup
      FilterPattern: '[version, account, eni, source, destination, srcport, destport="22" || destport="3389", protocol, packets, bytes, windowstart, windowend, action="ACCEPT", flowlogstatus]'
      MetricTransformations:
        - MetricName: ExternalRemoteConnections
          MetricNamespace: Security
          MetricValue: "1"

  RemoteAccessAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: ExternalSSHRDPAccess
      MetricName: ExternalRemoteConnections
      Namespace: Security
      Statistic: Sum
      Period: 300
      Threshold: 20
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref AlertTopic]
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Sid: AllowCloudWatchAlarms
            Effect: Allow
            Principal:
              Service: cloudwatch.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId""",
                terraform_template="""# Detect external SSH/RDP connections

variable "vpc_flow_logs_group" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "remote-access-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "ssh_rdp" {
  name           = "external-ssh-rdp"
  log_group_name = var.vpc_flow_logs_group
  pattern        = "[version, account, eni, source, destination, srcport, destport=\"22\" || destport=\"3389\", protocol, packets, bytes, windowstart, windowend, action=\"ACCEPT\", flowlogstatus]"

  metric_transformation {
    name      = "ExternalRemoteConnections"
    namespace = "Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "remote_access" {
  alarm_name          = "ExternalSSHRDPAccess"
  metric_name         = "ExternalRemoteConnections"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 20
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.alerts.arn]
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "alerts" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchAlarms"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="External SSH/RDP Access Detected",
                alert_description_template="Multiple SSH/RDP connections from external source {srcaddr}.",
                investigation_steps=[
                    "Identify source IP and check reputation",
                    "Review security group rules for overly permissive access",
                    "Check authentication logs on target instances",
                    "Review session activity for suspicious commands",
                    "Check for lateral movement attempts",
                    "Verify if access is authorised",
                ],
                containment_actions=[
                    "Block source IP in security groups",
                    "Restrict security group rules to known IPs",
                    "Rotate SSH keys and RDP credentials",
                    "Enable Session Manager instead of direct access",
                    "Review instance for compromise indicators",
                    "Enable MFA for RDP access",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Allowlist known administrator IPs and bastion hosts",
            detection_coverage="80% - catches SSH/RDP connections",
            evasion_considerations="Cannot evade if VPC Flow Logs enabled",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-15",
            prerequisites=["VPC Flow Logs enabled and sent to CloudWatch"],
        ),
        DetectionStrategy(
            strategy_id="t1133-aws-container-api",
            name="AWS Container API Exposure Detection",
            description="Detect exposed Docker/Kubernetes APIs on EC2 instances.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="vpc_flow_logs",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, srcaddr, dstaddr, dstport, action
| filter dstport in [2375, 2376, 10250, 6443]
| filter action = "ACCEPT"
| stats count(*) as connection_count by srcaddr, dstport, bin(1h)
| sort connection_count desc""",
                terraform_template="""# Detect exposed container APIs

variable "vpc_flow_logs_group" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "container-api-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "container_api" {
  name           = "container-api-exposure"
  log_group_name = var.vpc_flow_logs_group
  pattern        = "[version, account, eni, source, destination, srcport, destport=\"2375\" || destport=\"2376\" || destport=\"10250\" || destport=\"6443\", protocol, packets, bytes, windowstart, windowend, action=\"ACCEPT\", flowlogstatus]"

  metric_transformation {
    name      = "ContainerAPIAccess"
    namespace = "Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "container_api" {
  alarm_name          = "ContainerAPIExposure"
  metric_name         = "ContainerAPIAccess"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 5
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.alerts.arn]
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "alerts" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchAlarms"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}""",
                alert_severity="critical",
                alert_title="Container API Exposure Detected",
                alert_description_template="External access to container APIs (port {dstport}) from {srcaddr}.",
                investigation_steps=[
                    "Identify exposed container API type (Docker, Kubernetes)",
                    "Check for unauthorised container creation",
                    "Review container logs for suspicious activity",
                    "Check for deployed malicious containers",
                    "Review security group configurations",
                    "Check for cryptomining or backdoor containers",
                ],
                containment_actions=[
                    "Immediately block container API ports in security groups",
                    "Enable TLS authentication for container APIs",
                    "Remove unauthorised containers",
                    "Rotate all credentials and tokens",
                    "Review and remediate security group rules",
                    "Implement network segmentation",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Container APIs should never be exposed externally",
            detection_coverage="95% - catches container API access",
            evasion_considerations="Cannot evade if VPC Flow Logs enabled",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["VPC Flow Logs enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1133-gcp-iap-bypass",
            name="GCP Identity-Aware Proxy Bypass Detection",
            description="Detect attempts to bypass IAP or access remote services.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_instance"
protoPayload.methodName=~"(compute.instances.start|compute.sshKeys.create)"
OR (resource.type="gce_firewall" AND protoPayload.methodName="v1.compute.firewalls.patch" AND protoPayload.request.allowed.ports=~"(22|3389)")""",
                gcp_terraform_template="""# GCP: Detect remote service access and IAP bypass attempts

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "remote_access" {
  project = var.project_id
  name   = "external-remote-services"
  filter = <<-EOT
    resource.type="gce_instance"
    (protoPayload.methodName=~"compute.instances.start" OR
     protoPayload.methodName=~"compute.sshKeys.create")
    OR (resource.type="gce_firewall" AND
        protoPayload.methodName="v1.compute.firewalls.patch" AND
        protoPayload.request.allowed.ports=~"22|3389")
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "remote_access" {
  project      = var.project_id
  display_name = "External Remote Service Access"
  combiner     = "OR"
  conditions {
    display_name = "Suspicious remote access configuration"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.remote_access.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 3
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
                alert_title="GCP: External Remote Service Access",
                alert_description_template="Suspicious remote access configuration or IAP bypass attempt detected.",
                investigation_steps=[
                    "Review firewall rule changes",
                    "Check SSH key additions",
                    "Review instance start events",
                    "Check for IAP configuration changes",
                    "Review source IP addresses",
                    "Check for lateral movement",
                ],
                containment_actions=[
                    "Remove unauthorised SSH keys",
                    "Restore restrictive firewall rules",
                    "Enable VPC Service Controls",
                    "Enforce IAP for all remote access",
                    "Review and rotate credentials",
                    "Enable OS Login",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal SSH key management and firewall changes",
            detection_coverage="75% - catches configuration changes",
            evasion_considerations="May appear as legitimate administrative activity",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1133-gcp-ssh-rdp",
            name="GCP External SSH/RDP Detection",
            description="Detect external SSH/RDP connections to GCP instances.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="vpc_flow_logs",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gce_subnetwork"
jsonPayload.connection.dest_port=(22 OR 3389)
jsonPayload.connection.src_ip!="10.0.0.0/8"
jsonPayload.connection.src_ip!="172.16.0.0/12"
jsonPayload.connection.src_ip!="192.168.0.0/16"''',
                gcp_terraform_template="""# GCP: Detect external SSH/RDP connections

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email_s2" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "ssh_rdp_external" {
  project = var.project_id
  name   = "external-ssh-rdp-access"
  filter = <<-EOT
    resource.type="gce_subnetwork"
    (jsonPayload.connection.dest_port=22 OR jsonPayload.connection.dest_port=3389)
    jsonPayload.connection.src_ip!="10.0.0.0/8"
    jsonPayload.connection.src_ip!="172.16.0.0/12"
    jsonPayload.connection.src_ip!="192.168.0.0/16"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "ssh_rdp_external" {
  project      = var.project_id
  display_name = "External SSH/RDP Access"
  combiner     = "OR"
  conditions {
    display_name = "External remote connections detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.ssh_rdp_external.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 10
    }
  }
  notification_channels = [google_monitoring_notification_channel.email_s2.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }
}""",
                alert_severity="high",
                alert_title="GCP: External SSH/RDP Access",
                alert_description_template="External SSH/RDP connections detected from non-private IP addresses.",
                investigation_steps=[
                    "Identify source IP and check reputation",
                    "Review firewall rules for exposure",
                    "Check OS Login audit logs",
                    "Review instance activity",
                    "Check for lateral movement",
                    "Verify authorisation",
                ],
                containment_actions=[
                    "Update firewall rules to restrict access",
                    "Enable Identity-Aware Proxy",
                    "Remove unauthorised SSH keys",
                    "Enable OS Login with 2FA",
                    "Review instance for compromise",
                    "Implement bastion host architecture",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Allowlist known administrator public IPs",
            detection_coverage="85% - catches external connections",
            evasion_considerations="Cannot evade if VPC Flow Logs enabled",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-25",
            prerequisites=["VPC Flow Logs enabled"],
        ),
        # Azure Strategy: External Remote Services
        DetectionStrategy(
            strategy_id="t1133-azure",
            name="Azure External Remote Services Detection",
            description=(
                "Sentinel analytics detect unusual remote service usage. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.SENTINEL_RULE,
            aws_service="n/a",
            azure_service="sentinel",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                azure_kql_query="""// Direct KQL Query: Detect External Remote Service Access
// MITRE ATT&CK: T1133 - External Remote Services
// Data Sources: SigninLogs, AzureActivity, AzureDiagnostics

// Part 1: Detect VPN/External access sign-ins
let VPNSignins = SigninLogs
| where TimeGenerated > ago(24h)
| where AppDisplayName in ("VPN", "Azure Virtual Desktop", "Windows Virtual Desktop", "Microsoft Remote Desktop")
| where ResultType == 0  // Successful sign-in
| extend
    City = tostring(LocationDetails.city),
    Country = tostring(LocationDetails.countryOrRegion),
    IsRisky = RiskLevelDuringSignIn in ("high", "medium")
| summarize
    LoginCount = count(),
    Countries = make_set(Country, 5),
    Cities = make_set(City, 10),
    IPs = make_set(IPAddress, 10),
    RiskyLogins = countif(IsRisky),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by UserPrincipalName, AppDisplayName;
// Part 2: Detect VPN Gateway connections
let VPNConnections = AzureActivity
| where TimeGenerated > ago(24h)
| where OperationNameValue has_any ("Microsoft.Network/vpnGateways", "Microsoft.Network/virtualNetworkGateways")
| where OperationNameValue has_any ("connect", "startPacketCapture", "generateVpnProfile")
| summarize
    ConnectionCount = count(),
    Operations = make_set(OperationNameValue, 10),
    Gateways = make_set(Resource, 10),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by Caller, CallerIpAddress;
// Part 3: Detect exposed container APIs
let ContainerAPIAccess = AzureActivity
| where TimeGenerated > ago(24h)
| where OperationNameValue has_any (
    "Microsoft.ContainerService/managedClusters/listClusterAdminCredential",
    "Microsoft.ContainerRegistry/registries/listCredentials"
)
| summarize
    AccessCount = count(),
    Clusters = make_set(Resource, 10),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by Caller, CallerIpAddress;
// Combine results
VPNSignins
| project
    TimeGenerated = LastSeen,
    ServiceType = "VPN/Remote Desktop",
    Caller = UserPrincipalName,
    App = AppDisplayName,
    LoginCount,
    Countries,
    RiskyLogins,
    TechniqueId = "T1133",
    TechniqueName = "External Remote Services",
    Severity = case(
        RiskyLogins > 0, "High",
        LoginCount > 10, "Medium",
        "Low"
    )""",
                sentinel_rule_query="""// Sentinel Analytics Rule: External Remote Services Detection
// MITRE ATT&CK: T1133
// Detects VPN access, remote desktop, and container API exposure

// VPN and Remote Desktop sign-ins
SigninLogs
| where TimeGenerated > ago(24h)
| where AppDisplayName in ("VPN", "Azure Virtual Desktop", "Windows Virtual Desktop", "Microsoft Remote Desktop")
| where ResultType == 0
| extend
    Country = tostring(LocationDetails.countryOrRegion),
    IsRisky = RiskLevelDuringSignIn in ("high", "medium")
| summarize
    LoginCount = count(),
    Countries = make_set(Country, 5),
    IPs = make_set(IPAddress, 10),
    RiskyLogins = countif(IsRisky),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by UserPrincipalName, AppDisplayName
| where LoginCount > 5 or RiskyLogins > 0
| extend
    AccountName = tostring(split(UserPrincipalName, "@")[0]),
    AccountDomain = tostring(split(UserPrincipalName, "@")[1])
| project
    TimeGenerated = LastSeen,
    AccountName,
    AccountDomain,
    Caller = UserPrincipalName,
    AppDisplayName,
    LoginCount,
    Countries,
    IPs,
    RiskyLogins,
    FirstSeen""",
                azure_terraform_template="""# Azure Detection for External Remote Services
# MITRE ATT&CK: T1133
# Comprehensive detection for VPN, RDP, SSH, and container API access

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

variable "location" {
  type        = string
  description = "Azure region for resources"
  default     = "uksouth"
}

# Action Group for alerts
resource "azurerm_monitor_action_group" "security_alerts" {
  name                = "t1133-remote-services-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "T1133Alerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

#############################################################################
# Alert 1: VPN and Remote Desktop Sign-ins
# Detects VPN, AVD, and Remote Desktop sign-ins with risk assessment
#############################################################################
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "vpn_remote_desktop" {
  name                = "t1133-vpn-remote-desktop-signin"
  resource_group_name = var.resource_group_name
  location            = var.location

  evaluation_frequency = "PT5M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 2

  criteria {
    query = <<-QUERY
SigninLogs
| where TimeGenerated > ago(1h)
| where AppDisplayName in ("VPN", "Azure Virtual Desktop", "Windows Virtual Desktop", "Microsoft Remote Desktop")
| where ResultType == 0
| extend
    City = tostring(LocationDetails.city),
    Country = tostring(LocationDetails.countryOrRegion),
    IsRisky = RiskLevelDuringSignIn in ("high", "medium")
| summarize
    LoginCount = count(),
    Countries = make_set(Country, 5),
    Cities = make_set(City, 10),
    IPs = make_set(IPAddress, 10),
    RiskyLogins = countif(IsRisky),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by UserPrincipalName, AppDisplayName
| where LoginCount > 3 or RiskyLogins > 0
    QUERY

    time_aggregation_method = "Count"
    threshold               = 0
    operator                = "GreaterThan"

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  auto_mitigation_enabled = false

  action {
    action_groups = [azurerm_monitor_action_group.security_alerts.id]
  }

  description  = "Detects VPN and Remote Desktop sign-ins (T1133)"
  display_name = "T1133: VPN/Remote Desktop Access"
  enabled      = true

  tags = {
    "mitre-technique" = "T1133"
    "detection-type"  = "remote-access"
    "data-source"     = "SigninLogs"
  }
}

#############################################################################
# Alert 2: Risky VPN Sign-ins (High Severity)
# Detects sign-ins flagged as risky by Entra ID Protection
#############################################################################
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "risky_vpn_signin" {
  name                = "t1133-risky-vpn-signin"
  resource_group_name = var.resource_group_name
  location            = var.location

  evaluation_frequency = "PT5M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 1

  criteria {
    query = <<-QUERY
SigninLogs
| where TimeGenerated > ago(1h)
| where AppDisplayName in ("VPN", "Azure Virtual Desktop", "Windows Virtual Desktop", "Microsoft Remote Desktop")
| where RiskLevelDuringSignIn in ("high", "medium")
| project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName,
    RiskLevelDuringSignIn, RiskEventTypes_V2, RiskState,
    Country = tostring(LocationDetails.countryOrRegion),
    City = tostring(LocationDetails.city),
    DeviceDetail, ConditionalAccessStatus
    QUERY

    time_aggregation_method = "Count"
    threshold               = 0
    operator                = "GreaterThan"

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  auto_mitigation_enabled = false

  action {
    action_groups = [azurerm_monitor_action_group.security_alerts.id]
  }

  description  = "Detects risky VPN/Remote Desktop sign-ins (T1133)"
  display_name = "T1133: Risky Remote Access Sign-in"
  enabled      = true

  tags = {
    "mitre-technique" = "T1133"
    "detection-type"  = "risky-signin"
    "data-source"     = "SigninLogs"
    "severity"        = "high"
  }
}

#############################################################################
# Alert 3: VPN Gateway Operations
# Detects VPN gateway connections and profile generation
#############################################################################
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "vpn_gateway_ops" {
  name                = "t1133-vpn-gateway-operations"
  resource_group_name = var.resource_group_name
  location            = var.location

  evaluation_frequency = "PT5M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 2

  criteria {
    query = <<-QUERY
AzureActivity
| where TimeGenerated > ago(1h)
| where OperationNameValue has_any (
    "Microsoft.Network/vpnGateways",
    "Microsoft.Network/virtualNetworkGateways"
)
| where OperationNameValue has_any (
    "connect", "startPacketCapture", "generateVpnProfile",
    "getVpnClientConnectionHealth", "disconnect"
)
| where ActivityStatusValue in ("Success", "Succeeded", "Started")
| project TimeGenerated, Caller, CallerIpAddress, Resource,
    ResourceGroup, SubscriptionId, OperationNameValue
| extend GatewayName = tostring(split(Resource, "/")[-1])
    QUERY

    time_aggregation_method = "Count"
    threshold               = 0
    operator                = "GreaterThan"

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  auto_mitigation_enabled = false

  action {
    action_groups = [azurerm_monitor_action_group.security_alerts.id]
  }

  description  = "Detects VPN gateway operations (T1133)"
  display_name = "T1133: VPN Gateway Operation"
  enabled      = true

  tags = {
    "mitre-technique" = "T1133"
    "detection-type"  = "vpn-gateway"
    "data-source"     = "AzureActivity"
  }
}

#############################################################################
# Alert 4: AKS/Container Admin Credential Access
# Detects attempts to retrieve cluster admin credentials (container API exposure)
#############################################################################
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "container_api_access" {
  name                = "t1133-container-api-cred-access"
  resource_group_name = var.resource_group_name
  location            = var.location

  evaluation_frequency = "PT5M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 1

  criteria {
    query = <<-QUERY
AzureActivity
| where TimeGenerated > ago(1h)
| where OperationNameValue has_any (
    "Microsoft.ContainerService/managedClusters/listClusterAdminCredential",
    "Microsoft.ContainerService/managedClusters/listClusterUserCredential",
    "Microsoft.ContainerRegistry/registries/listCredentials"
)
| where ActivityStatusValue in ("Success", "Succeeded")
| project TimeGenerated, Caller, CallerIpAddress, Resource,
    ResourceGroup, SubscriptionId, OperationNameValue
| extend ResourceName = tostring(split(Resource, "/")[-1])
    QUERY

    time_aggregation_method = "Count"
    threshold               = 0
    operator                = "GreaterThan"

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  auto_mitigation_enabled = false

  action {
    action_groups = [azurerm_monitor_action_group.security_alerts.id]
  }

  description  = "Detects container API credential access (T1133)"
  display_name = "T1133: Container API Credential Access"
  enabled      = true

  tags = {
    "mitre-technique" = "T1133"
    "detection-type"  = "container-api"
    "data-source"     = "AzureActivity"
    "severity"        = "high"
  }
}

#############################################################################
# Alert 5: Azure Bastion Sessions
# Detects Azure Bastion connections (legitimate but should be monitored)
#############################################################################
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "bastion_sessions" {
  name                = "t1133-bastion-sessions"
  resource_group_name = var.resource_group_name
  location            = var.location

  evaluation_frequency = "PT10M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 3

  criteria {
    query = <<-QUERY
AzureDiagnostics
| where TimeGenerated > ago(1h)
| where ResourceType == "BASTIONHOSTS"
| where OperationName has_any ("BastionHostOperationalLog", "BastionAuditLogs")
| summarize SessionCount = count(),
    TargetVMs = make_set(targetResourceId_s, 10),
    SourceIPs = make_set(clientIpAddress_s, 10)
    by userName_s, bastionHostName_s, bin(TimeGenerated, 10m)
| where SessionCount > 5
| project TimeGenerated, userName_s, bastionHostName_s,
    SessionCount, TargetVMs, SourceIPs
    QUERY

    time_aggregation_method = "Count"
    threshold               = 0
    operator                = "GreaterThan"

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  auto_mitigation_enabled = false

  action {
    action_groups = [azurerm_monitor_action_group.security_alerts.id]
  }

  description  = "Detects Azure Bastion session activity (T1133)"
  display_name = "T1133: Azure Bastion Sessions"
  enabled      = true

  tags = {
    "mitre-technique" = "T1133"
    "detection-type"  = "bastion"
    "data-source"     = "AzureDiagnostics"
  }
}

#############################################################################
# Alert 6: NSG Flow Logs - External SSH/RDP Access
# Detects external SSH (22) and RDP (3389) connections
#############################################################################
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "external_ssh_rdp" {
  name                = "t1133-external-ssh-rdp"
  resource_group_name = var.resource_group_name
  location            = var.location

  evaluation_frequency = "PT5M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 2

  criteria {
    query = <<-QUERY
AzureDiagnostics
| where TimeGenerated > ago(1h)
| where Category == "NetworkSecurityGroupFlowEvent"
| extend FlowLog = parse_json(flowLog_s)
| mv-expand FlowLog
| extend
    SourceIP = tostring(split(FlowLog.flows[0].flowTuples[0], ",")[0]),
    DestPort = toint(split(FlowLog.flows[0].flowTuples[0], ",")[4]),
    FlowDirection = tostring(FlowLog.flows[0].flowTuples[0])
| where DestPort in (22, 3389)
| where FlowDirection has "I"
| where SourceIP !startswith "10." and SourceIP !startswith "172." and SourceIP !startswith "192.168."
| summarize ConnectionCount = count(),
    SourceIPs = make_set(SourceIP, 20)
    by DestPort, Resource, bin(TimeGenerated, 10m)
| where ConnectionCount > 10
| extend ProtocolName = case(DestPort == 22, "SSH", DestPort == 3389, "RDP", "Unknown")
    QUERY

    time_aggregation_method = "Count"
    threshold               = 0
    operator                = "GreaterThan"

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  auto_mitigation_enabled = false

  action {
    action_groups = [azurerm_monitor_action_group.security_alerts.id]
  }

  description  = "Detects external SSH/RDP connections via NSG Flow Logs (T1133)"
  display_name = "T1133: External SSH/RDP Access"
  enabled      = true

  tags = {
    "mitre-technique" = "T1133"
    "detection-type"  = "network-flow"
    "data-source"     = "AzureDiagnostics-NSGFlowLogs"
  }
}

#############################################################################
# Alert 7: Failed Remote Access Attempts (Brute Force Indicator)
# Detects multiple failed VPN/Remote Desktop sign-in attempts
#############################################################################
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "failed_remote_access" {
  name                = "t1133-failed-remote-access"
  resource_group_name = var.resource_group_name
  location            = var.location

  evaluation_frequency = "PT5M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 2

  criteria {
    query = <<-QUERY
SigninLogs
| where TimeGenerated > ago(1h)
| where AppDisplayName in ("VPN", "Azure Virtual Desktop", "Windows Virtual Desktop", "Microsoft Remote Desktop")
| where ResultType != 0
| summarize FailedCount = count(),
    ResultCodes = make_set(ResultType, 10),
    IPs = make_set(IPAddress, 10)
    by UserPrincipalName, AppDisplayName, bin(TimeGenerated, 10m)
| where FailedCount > 5
| project TimeGenerated, UserPrincipalName, AppDisplayName,
    FailedCount, ResultCodes, IPs
    QUERY

    time_aggregation_method = "Count"
    threshold               = 0
    operator                = "GreaterThan"

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  auto_mitigation_enabled = false

  action {
    action_groups = [azurerm_monitor_action_group.security_alerts.id]
  }

  description  = "Detects failed remote access attempts indicating brute force (T1133)"
  display_name = "T1133: Failed Remote Access Attempts"
  enabled      = true

  tags = {
    "mitre-technique" = "T1133"
    "detection-type"  = "brute-force"
    "data-source"     = "SigninLogs"
  }
}

output "vpn_remote_desktop_alert_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.vpn_remote_desktop.id
}

output "risky_vpn_alert_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.risky_vpn_signin.id
}

output "vpn_gateway_alert_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.vpn_gateway_ops.id
}

output "container_api_alert_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.container_api_access.id
}

output "bastion_alert_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.bastion_sessions.id
}

output "external_ssh_rdp_alert_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.external_ssh_rdp.id
}

output "failed_remote_access_alert_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.failed_remote_access.id
}""",
                alert_severity="high",
                alert_title="Azure: External Remote Services Detected",
                alert_description_template=(
                    "External Remote Services activity detected. "
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
        "t1133-aws-container-api",  # Critical - often exploited
        "t1133-aws-ec2-ssh-rdp",  # High impact detection
        "t1133-aws-vpn-unusual",  # Catch VPN abuse
        "t1133-gcp-ssh-rdp",  # GCP external access
        "t1133-gcp-iap-bypass",  # GCP IAP protection
    ],
    total_effort_hours=7.5,
    coverage_improvement="+18% improvement for Initial Access and Persistence tactics",
)
