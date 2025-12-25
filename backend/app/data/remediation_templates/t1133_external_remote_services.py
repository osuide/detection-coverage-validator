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
      AlarmActions: [!Ref AlertTopic]""",
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
  alarm_actions       = [aws_sns_topic.alerts.arn]
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
      AlarmActions: [!Ref AlertTopic]""",
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
  alarm_actions       = [aws_sns_topic.alerts.arn]
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
  alarm_actions       = [aws_sns_topic.alerts.arn]
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

resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "remote_access" {
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
  notification_channels = [google_monitoring_notification_channel.email.id]
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

resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "ssh_rdp_external" {
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
  notification_channels = [google_monitoring_notification_channel.email.id]
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
