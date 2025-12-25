"""
T1562.007 - Impair Defenses: Disable or Modify Cloud Firewall

Adversaries disable or modify firewalls within cloud environments to bypass
access controls. This includes modifying security groups, firewall rules, and
network policies to permit unauthorised access and facilitate malicious activities.
Used by Pacu.
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
    technique_id="T1562.007",
    technique_name="Impair Defenses: Disable or Modify Cloud Firewall",
    tactic_ids=["TA0005"],
    mitre_url="https://attack.mitre.org/techniques/T1562/007/",
    threat_context=ThreatContext(
        description=(
            "Adversaries disable or modify cloud firewalls to bypass access controls and "
            "network restrictions. This includes creating permissive security groups, "
            "modifying firewall rules to allow 0.0.0.0/0 access, removing network limitations, "
            "and enabling unauthorised command and control communications, lateral movement, "
            "data exfiltration, cryptomining, brute force attacks, and denial of service operations."
        ),
        attacker_goal="Bypass network access controls by disabling or modifying cloud firewall rules",
        why_technique=[
            "Bypass network restrictions for C2 communications",
            "Enable lateral movement across cloud networks",
            "Permit data exfiltration channels",
            "Remove mining/resource abuse limitations",
            "Facilitate brute force and DoS attacks",
            "Open access for persistent backdoors",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="uncommon",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "High-impact defense evasion technique that can enable multiple attack vectors. "
            "Modifying cloud firewalls removes critical security controls and creates "
            "persistent access channels for adversaries."
        ),
        business_impact=[
            "Bypassed network security controls",
            "Unauthorised network access enabler",
            "Data exfiltration risk",
            "Compliance violations",
            "Lateral movement facilitation",
        ],
        typical_attack_phase="defense_evasion",
        often_precedes=["T1071", "T1090", "T1048", "T1021"],
        often_follows=["T1078.004", "T1098"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1562-007-aws-sg-modify",
            name="AWS Security Group Modification Detection",
            description="Detect unauthorised creation, deletion, or modification of AWS security groups.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudtrail",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.principalId, eventName, requestParameters.groupId, requestParameters.ipPermissions
| filter eventName in ["AuthorizeSecurityGroupIngress", "AuthorizeSecurityGroupEgress", "RevokeSecurityGroupIngress", "RevokeSecurityGroupEgress", "CreateSecurityGroup", "DeleteSecurityGroup"]
| filter requestParameters.ipPermissions.items.0.ipRanges.items.0.cidrIp = "0.0.0.0/0" or requestParameters.ipPermissions.items.0.ipv6Ranges.items.0.cidrIpv6 = "::/0"
| stats count(*) as modifications by userIdentity.principalId, eventName, bin(5m)
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect unauthorised security group modifications

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
      KmsMasterKeyId: alias/aws/sns
      DisplayName: Security Group Modification Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Create metric filter for security group changes
  SecurityGroupModificationFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventName = "AuthorizeSecurityGroupIngress") || ($.eventName = "AuthorizeSecurityGroupEgress") || ($.eventName = "RevokeSecurityGroupIngress") || ($.eventName = "RevokeSecurityGroupEgress") || ($.eventName = "CreateSecurityGroup") || ($.eventName = "DeleteSecurityGroup") }'
      MetricTransformations:
        - MetricName: SecurityGroupModifications
          MetricNamespace: Security/Firewall
          MetricValue: "1"

  # Step 3: Create alarm for security group modifications
  SecurityGroupModificationAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: UnauthorisedSecurityGroupModification
      AlarmDescription: Alert on security group modifications that may bypass firewall controls
      MetricName: SecurityGroupModifications
      Namespace: Security/Firewall
      Statistic: Sum
      Period: 300
      Threshold: 5
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching
      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect unauthorised security group modifications

variable "cloudtrail_log_group" {
  type        = string
  description = "CloudTrail log group name"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "sg_alerts" {
  name         = "security-group-modification-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "Security Group Modification Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.sg_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for security group changes
resource "aws_cloudwatch_log_metric_filter" "sg_modifications" {
  name           = "security-group-modifications"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventName = \"AuthorizeSecurityGroupIngress\") || ($.eventName = \"AuthorizeSecurityGroupEgress\") || ($.eventName = \"RevokeSecurityGroupIngress\") || ($.eventName = \"RevokeSecurityGroupEgress\") || ($.eventName = \"CreateSecurityGroup\") || ($.eventName = \"DeleteSecurityGroup\") }"

  metric_transformation {
    name      = "SecurityGroupModifications"
    namespace = "Security/Firewall"
    value     = "1"
  }
}

# Step 3: Create alarm for security group modifications
resource "aws_cloudwatch_metric_alarm" "sg_modification_alert" {
  alarm_name          = "UnauthorisedSecurityGroupModification"
  alarm_description   = "Alert on security group modifications that may bypass firewall controls"
  metric_name         = "SecurityGroupModifications"
  namespace           = "Security/Firewall"
  statistic           = "Sum"
  period              = 300
  threshold           = 5
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.sg_alerts.arn]
}""",
                alert_severity="high",
                alert_title="Unauthorised Security Group Modification Detected",
                alert_description_template="Security group modification by {principalId}: {eventName} on {groupId}.",
                investigation_steps=[
                    "Review the security group changes and identify rules permitting 0.0.0.0/0 or ::/0",
                    "Verify the IAM principal has authorisation to modify security groups",
                    "Check for associated privileged role activity or credential compromise",
                    "Review CloudTrail logs for the timeframe before and after the modification",
                    "Identify affected resources using the modified security group",
                    "Check GuardDuty for related findings or allowlist modifications",
                ],
                containment_actions=[
                    "Revert unauthorised security group changes immediately",
                    "Review and restrict IAM permissions for security group modifications",
                    "Enable MFA for security group modification actions",
                    "Isolate affected resources if compromise is suspected",
                    "Review all security groups for overly permissive rules",
                    "Enable AWS Config rules to prevent 0.0.0.0/0 ingress",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Filter for authorised security principals or exclude known maintenance windows",
            detection_coverage="80% - covers CloudTrail-logged security group modifications",
            evasion_considerations="Adversaries with CloudTrail logging disabled or using compromised privileged accounts may evade detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30-60 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled with CloudWatch Logs integration"],
        ),
        DetectionStrategy(
            strategy_id="t1562-007-aws-nacl-modify",
            name="AWS Network ACL Modification Detection",
            description="Detect unauthorised modifications to Network ACLs that may bypass network controls.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudtrail",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.principalId, eventName, requestParameters.networkAclId
| filter eventName in ["CreateNetworkAcl", "CreateNetworkAclEntry", "DeleteNetworkAcl", "DeleteNetworkAclEntry", "ReplaceNetworkAclEntry", "ReplaceNetworkAclAssociation"]
| stats count(*) as modifications by userIdentity.principalId, eventName, bin(5m)
| sort @timestamp desc""",
                terraform_template="""# Detect unauthorised Network ACL modifications

variable "cloudtrail_log_group" {
  type        = string
  description = "CloudTrail log group name"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "nacl_alerts" {
  name         = "network-acl-modification-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "Network ACL Modification Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.nacl_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for NACL changes
resource "aws_cloudwatch_log_metric_filter" "nacl_modifications" {
  name           = "network-acl-modifications"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventName = \"CreateNetworkAcl\") || ($.eventName = \"CreateNetworkAclEntry\") || ($.eventName = \"DeleteNetworkAcl\") || ($.eventName = \"DeleteNetworkAclEntry\") || ($.eventName = \"ReplaceNetworkAclEntry\") || ($.eventName = \"ReplaceNetworkAclAssociation\") }"

  metric_transformation {
    name      = "NetworkACLModifications"
    namespace = "Security/Firewall"
    value     = "1"
  }
}

# Step 3: Create alarm for NACL modifications
resource "aws_cloudwatch_metric_alarm" "nacl_modification_alert" {
  alarm_name          = "UnauthorisedNetworkACLModification"
  alarm_description   = "Alert on Network ACL modifications that may bypass firewall controls"
  metric_name         = "NetworkACLModifications"
  namespace           = "Security/Firewall"
  statistic           = "Sum"
  period              = 300
  threshold           = 3
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.nacl_alerts.arn]
}""",
                alert_severity="high",
                alert_title="Unauthorised Network ACL Modification Detected",
                alert_description_template="Network ACL modification by {principalId}: {eventName}.",
                investigation_steps=[
                    "Review the Network ACL changes and identify permissive rules",
                    "Verify the IAM principal is authorised to modify Network ACLs",
                    "Check for associated VPC changes or subnet associations",
                    "Review related CloudTrail events for pattern analysis",
                    "Identify affected subnets and resources",
                    "Check for subsequent lateral movement or data exfiltration",
                ],
                containment_actions=[
                    "Revert unauthorised Network ACL changes",
                    "Review and restrict IAM permissions for NACL modifications",
                    "Audit all Network ACLs for overly permissive rules",
                    "Enable MFA for infrastructure modification actions",
                    "Implement AWS Config rules for NACL compliance",
                    "Review VPC flow logs for suspicious traffic patterns",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Network ACL changes are infrequent; authorise legitimate administrative accounts",
            detection_coverage="75% - covers CloudTrail-logged NACL modifications",
            evasion_considerations="Adversaries may use legitimate accounts or disable logging",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30-60 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled with CloudWatch Logs integration"],
        ),
        DetectionStrategy(
            strategy_id="t1562-007-gcp-firewall-modify",
            name="GCP Firewall Rule Modification Detection",
            description="Detect unauthorised creation, deletion, or modification of GCP firewall rules.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_firewall_rule"
protoPayload.methodName=~"^.*firewalls\\.(insert|delete|patch|update)$"
(protoPayload.request.sourceRanges="0.0.0.0/0" OR protoPayload.request.sourceRanges="::/0")""",
                gcp_terraform_template="""# GCP: Detect unauthorised firewall rule modifications

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: Create notification channel for alerts
resource "google_monitoring_notification_channel" "email" {
  project      = var.project_id
  display_name = "Firewall Modification Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log-based metric for firewall modifications
resource "google_logging_metric" "firewall_modifications" {
  project = var.project_id
  name    = "firewall-rule-modifications"
  filter  = <<-EOT
    resource.type="gce_firewall_rule"
    protoPayload.methodName=~"^.*firewalls\\.(insert|delete|patch|update)$"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "principal"
      value_type  = "STRING"
      description = "Principal making the change"
    }
  }

  label_extractors = {
    "principal" = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
  }
}

# Step 3: Create alert policy for firewall modifications
resource "google_monitoring_alert_policy" "firewall_modification_alert" {
  project      = var.project_id
  display_name = "Unauthorised Firewall Rule Modification"
  combiner     = "OR"

  conditions {
    display_name = "Firewall rule modified"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.firewall_modifications.name}\" resource.type=\"gce_firewall_rule\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 3
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]
  alert_strategy {
    auto_close = "1800s"
  }
}""",
                alert_severity="high",
                alert_title="GCP: Unauthorised Firewall Rule Modification",
                alert_description_template="Firewall rule modification detected in GCP project.",
                investigation_steps=[
                    "Review the firewall rule changes and identify rules permitting 0.0.0.0/0 or ::/0",
                    "Verify the principal has authorisation to modify firewall rules",
                    "Check for associated IAM policy changes or privilege escalation",
                    "Review Cloud Audit Logs for the timeframe surrounding the modification",
                    "Identify affected VPC networks and resources",
                    "Check Security Command Centre for related findings",
                ],
                containment_actions=[
                    "Revert unauthorised firewall rule changes immediately",
                    "Review and restrict IAM permissions for firewall modifications",
                    "Enable organisation policy constraints for firewall rules",
                    "Implement VPC Service Controls for network perimeter protection",
                    "Audit all firewall rules for overly permissive configurations",
                    "Review VPC flow logs for suspicious traffic patterns",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude authorised service accounts and infrastructure-as-code deployments",
            detection_coverage="80% - covers Cloud Audit Logs-logged firewall modifications",
            evasion_considerations="Adversaries may use legitimate service accounts or disable audit logging",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30-60 minutes",
            estimated_monthly_cost="$10-15",
            prerequisites=["Cloud Audit Logs enabled for compute.googleapis.com"],
        ),
        DetectionStrategy(
            strategy_id="t1562-007-aws-guardduty-suppress",
            name="AWS GuardDuty Suppression Detection",
            description="Detect attempts to suppress or disable AWS GuardDuty findings and IP allowlisting.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudtrail",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.principalId, eventName, requestParameters
| filter eventSource = "guardduty.amazonaws.com"
| filter eventName in ["CreateFilter", "UpdateFilter", "CreateIPSet", "UpdateIPSet", "CreateThreatIntelSet", "UpdateThreatIntelSet", "StopMonitoringMembers", "DisassociateMembers"]
| stats count(*) as suppressions by userIdentity.principalId, eventName, bin(5m)
| sort @timestamp desc""",
                terraform_template="""# Detect GuardDuty suppression and allowlisting attempts

variable "cloudtrail_log_group" {
  type        = string
  description = "CloudTrail log group name"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "guardduty_alerts" {
  name         = "guardduty-suppression-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "GuardDuty Suppression Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.guardduty_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for GuardDuty suppression
resource "aws_cloudwatch_log_metric_filter" "guardduty_suppression" {
  name           = "guardduty-suppression-attempts"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventSource = \"guardduty.amazonaws.com\") && (($.eventName = \"CreateFilter\") || ($.eventName = \"UpdateFilter\") || ($.eventName = \"CreateIPSet\") || ($.eventName = \"UpdateIPSet\") || ($.eventName = \"CreateThreatIntelSet\") || ($.eventName = \"UpdateThreatIntelSet\")) }"

  metric_transformation {
    name      = "GuardDutySuppressionAttempts"
    namespace = "Security/Firewall"
    value     = "1"
  }
}

# Step 3: Create alarm for GuardDuty suppression
resource "aws_cloudwatch_metric_alarm" "guardduty_suppression_alert" {
  alarm_name          = "GuardDutySuppressionDetected"
  alarm_description   = "Alert on attempts to suppress GuardDuty findings or allowlist IPs"
  metric_name         = "GuardDutySuppressionAttempts"
  namespace           = "Security/Firewall"
  statistic           = "Sum"
  period              = 300
  threshold           = 1
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.guardduty_alerts.arn]
}""",
                alert_severity="critical",
                alert_title="GuardDuty Suppression or Allowlisting Detected",
                alert_description_template="GuardDuty suppression activity by {principalId}: {eventName}.",
                investigation_steps=[
                    "Review the GuardDuty filter, IPSet, or ThreatIntelSet modifications",
                    "Verify the IAM principal has legitimate authorisation to modify GuardDuty",
                    "Check for patterns indicating Pacu framework usage or automated tooling",
                    "Review CloudTrail for associated credential compromise or privilege escalation",
                    "Identify suppressed findings that may indicate ongoing attacks",
                    "Check for concurrent security group or firewall modifications",
                ],
                containment_actions=[
                    "Revert GuardDuty suppressions and allowlists immediately",
                    "Review and investigate any suppressed GuardDuty findings",
                    "Restrict IAM permissions for GuardDuty configuration changes",
                    "Enable MFA for GuardDuty modification actions",
                    "Review all GuardDuty filters and trusted IP lists",
                    "Investigate the principal for credential compromise",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="GuardDuty modifications are rare; authorise only security team principals",
            detection_coverage="90% - covers CloudTrail-logged GuardDuty modifications",
            evasion_considerations="Adversaries may use legitimate security team credentials",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30-60 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=[
                "CloudTrail enabled with CloudWatch Logs integration",
                "GuardDuty enabled",
            ],
        ),
    ],
    recommended_order=[
        "t1562-007-aws-sg-modify",
        "t1562-007-gcp-firewall-modify",
        "t1562-007-aws-guardduty-suppress",
        "t1562-007-aws-nacl-modify",
    ],
    total_effort_hours=3.0,
    coverage_improvement="+25% improvement for Defense Evasion tactic",
)
