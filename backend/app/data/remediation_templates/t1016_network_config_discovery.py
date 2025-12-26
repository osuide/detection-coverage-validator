"""
T1016 - System Network Configuration Discovery

Adversaries investigate network configuration details including IP/MAC addresses,
routing information, and network interfaces to understand the environment and
identify targets for lateral movement and further exploitation.
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
    technique_id="T1016",
    technique_name="System Network Configuration Discovery",
    tactic_ids=["TA0007"],
    mitre_url="https://attack.mitre.org/techniques/T1016/",
    threat_context=ThreatContext(
        description=(
            "Adversaries investigate network configuration details including IP/MAC addresses, "
            "routing tables, network interfaces, and VPC configurations. In cloud environments, "
            "this includes enumerating VPCs, subnets, security groups, network ACLs, and routing "
            "tables. This reconnaissance helps adversaries understand network topology, identify "
            "network-accessible targets, and plan lateral movement paths."
        ),
        attacker_goal="Map network configuration to identify lateral movement paths and accessible resources",
        why_technique=[
            "Identifies network topology and connectivity",
            "Reveals routing paths and network boundaries",
            "Maps security group and firewall rules",
            "Discovers network interfaces and IP addresses",
            "Enables lateral movement planning",
            "Identifies VPC peering and interconnections",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="very_common",
        trend="increasing",
        severity_score=4,
        severity_reasoning=(
            "Discovery technique with moderate impact. Common post-compromise activity. "
            "Indicates active reconnaissance and planning for lateral movement. "
            "Often precedes more damaging attacks."
        ),
        business_impact=[
            "Reveals network architecture",
            "Identifies network segmentation gaps",
            "Exposes routing and connectivity",
            "Early warning for lateral movement",
            "Indicates compromised credentials",
        ],
        typical_attack_phase="discovery",
        often_precedes=["T1021", "T1570", "T1210"],
        often_follows=["T1078.004", "T1059.009", "T1580"],
    ),
    detection_strategies=[
        # Strategy 1: AWS - VPC/Network Configuration Enumeration
        DetectionStrategy(
            strategy_id="t1016-aws-network",
            name="AWS Network Configuration Discovery Detection",
            description="Detect enumeration of VPCs, subnets, routing tables, network interfaces, and security groups.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, userIdentity.arn, eventSource, requestParameters
| filter eventName in ["DescribeVpcs", "DescribeSubnets", "DescribeRouteTables", "DescribeNetworkInterfaces", "DescribeSecurityGroups", "DescribeNetworkAcls", "DescribeVpcPeeringConnections", "DescribeTransitGateways", "DescribeNatGateways"]
| stats count(*) as network_enum_count by userIdentity.arn, bin(1h)
| filter network_enum_count > 30
| sort network_enum_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect network configuration discovery activity

Parameters:
  CloudTrailLogGroup:
    Type: String
    Description: CloudWatch Logs group receiving CloudTrail events
  AlertEmail:
    Type: String
    Description: Email address for security alerts

Resources:
  # Step 1: SNS topic for alerts
  NetworkDiscoveryAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: Network Configuration Discovery Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter for network discovery
  NetworkDiscoveryFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventName = "DescribeVpcs" || $.eventName = "DescribeSubnets" || $.eventName = "DescribeRouteTables" || $.eventName = "DescribeNetworkInterfaces" || $.eventName = "DescribeSecurityGroups" || $.eventName = "DescribeNetworkAcls") }'
      MetricTransformations:
        - MetricName: NetworkConfigDiscovery
          MetricNamespace: SecurityDetection
          MetricValue: "1"
          DefaultValue: 0

  # Step 3: CloudWatch alarm for suspicious volume
  NetworkDiscoveryAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: NetworkConfigurationDiscoveryDetected
      AlarmDescription: High volume of network configuration discovery API calls detected
      MetricName: NetworkConfigDiscovery
      Namespace: SecurityDetection
      Statistic: Sum
      Period: 300
      Threshold: 50
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching
      AlarmActions:
        - !Ref NetworkDiscoveryAlertTopic

  # Step 4: SNS topic policy (scoped)
  AlertTopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Sid: AllowCloudWatchAlarms
            Effect: Allow
            Principal:
              Service: cloudwatch.amazonaws.com
            Action: sns:Publish
            Resource: !Ref NetworkDiscoveryAlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
      Topics:
        - !Ref NetworkDiscoveryAlertTopic""",
                terraform_template="""# AWS: Detect network configuration discovery

variable "cloudtrail_log_group" {
  type        = string
  description = "CloudWatch Logs group receiving CloudTrail events"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "network_discovery_alerts" {
  name         = "network-configuration-discovery-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "Network Configuration Discovery Alerts"
}

resource "aws_sns_topic_subscription" "email_alerts" {
  topic_arn = aws_sns_topic.network_discovery_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for network discovery
resource "aws_cloudwatch_log_metric_filter" "network_discovery" {
  name           = "network-configuration-discovery"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventName = \"DescribeVpcs\" || $.eventName = \"DescribeSubnets\" || $.eventName = \"DescribeRouteTables\" || $.eventName = \"DescribeNetworkInterfaces\" || $.eventName = \"DescribeSecurityGroups\" || $.eventName = \"DescribeNetworkAcls\") }"

  metric_transformation {
    name          = "NetworkConfigDiscovery"
    namespace     = "SecurityDetection"
    value         = "1"
    default_value = 0
  }
}

# Step 3: CloudWatch alarm for suspicious volume
resource "aws_cloudwatch_metric_alarm" "network_discovery" {
  alarm_name          = "NetworkConfigurationDiscoveryDetected"
  alarm_description   = "High volume of network configuration discovery API calls detected"
  metric_name         = "NetworkConfigDiscovery"
  namespace           = "SecurityDetection"
  statistic           = "Sum"
  period              = 300
  threshold           = 50
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.network_discovery_alerts.arn]
}

# Step 4: SNS topic policy (scoped to account)
data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.network_discovery_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchAlarms"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.network_discovery_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}""",
                alert_severity="medium",
                alert_title="Network Configuration Discovery Detected",
                alert_description_template="High volume of network configuration discovery API calls from {userIdentity.arn}. {network_enum_count} network enumeration calls in 1 hour.",
                investigation_steps=[
                    "Identify the principal performing network discovery",
                    "Verify if this is authorised security scanning or infrastructure automation",
                    "Review what specific network resources were enumerated",
                    "Check for unusual access patterns or timing",
                    "Look for follow-on lateral movement or resource access attempts",
                    "Review CloudTrail for other suspicious activity from same principal",
                    "Verify source IP address and geolocation",
                ],
                containment_actions=[
                    "Review and restrict IAM permissions for ec2:Describe* actions",
                    "Monitor for subsequent lateral movement attempts",
                    "Consider implementing VPC endpoint policies to limit discovery",
                    "Enable VPC Flow Logs for network traffic monitoring",
                    "Audit recent changes to security groups and network ACLs",
                    "If unauthorised, rotate compromised credentials immediately",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Whitelist infrastructure automation tools, CSPM scanners, monitoring solutions, and DevOps CI/CD pipelines. Adjust threshold based on environment size.",
            detection_coverage="75% - volume-based detection covers bulk enumeration",
            evasion_considerations="Slow, throttled enumeration below threshold evades detection. Legitimate permissions make activity appear normal.",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=[
                "CloudTrail logging to CloudWatch Logs",
                "EC2 read events logged",
            ],
        ),
        # Strategy 2: AWS - Network Interface Metadata Access
        DetectionStrategy(
            strategy_id="t1016-aws-eni-metadata",
            name="AWS Network Interface Detail Enumeration",
            description="Detect detailed enumeration of network interface attributes including IP addresses and MAC addresses.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, userIdentity.arn, requestParameters.networkInterfaceId
| filter eventName = "DescribeNetworkInterfaces" or eventName = "DescribeNetworkInterfaceAttribute"
| stats count(*) as eni_enum_count by userIdentity.arn, bin(30m)
| filter eni_enum_count > 20
| sort eni_enum_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect network interface enumeration

Parameters:
  CloudTrailLogGroup:
    Type: String
  AlertEmail:
    Type: String

Resources:
  # Step 1: SNS topic
  ENIDiscoveryAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter
  ENIDiscoveryFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventName = "DescribeNetworkInterfaces" || $.eventName = "DescribeNetworkInterfaceAttribute") }'
      MetricTransformations:
        - MetricName: ENIEnumeration
          MetricNamespace: SecurityDetection
          MetricValue: "1"

  # Step 3: Alarm
  ENIDiscoveryAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: NetworkInterfaceEnumerationDetected
      MetricName: ENIEnumeration
      Namespace: SecurityDetection
      Statistic: Sum
      Period: 1800
      Threshold: 30
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching
      AlarmActions: [!Ref ENIDiscoveryAlertTopic]

  # Step 4: SNS topic policy (scoped)
  AlertTopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Sid: AllowCloudWatchAlarms
            Effect: Allow
            Principal:
              Service: cloudwatch.amazonaws.com
            Action: sns:Publish
            Resource: !Ref ENIDiscoveryAlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
      Topics:
        - !Ref ENIDiscoveryAlertTopic""",
                terraform_template="""# AWS: Detect network interface enumeration

variable "cloudtrail_log_group" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "eni_discovery_alerts" {
  name = "network-interface-enumeration-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.eni_discovery_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter
resource "aws_cloudwatch_log_metric_filter" "eni_discovery" {
  name           = "network-interface-enumeration"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventName = \"DescribeNetworkInterfaces\" || $.eventName = \"DescribeNetworkInterfaceAttribute\") }"

  metric_transformation {
    name      = "ENIEnumeration"
    namespace = "SecurityDetection"
    value     = "1"
  }
}

# Step 3: Alarm
resource "aws_cloudwatch_metric_alarm" "eni_discovery" {
  alarm_name          = "NetworkInterfaceEnumerationDetected"
  alarm_description   = "High volume of network interface enumeration detected"
  metric_name         = "ENIEnumeration"
  namespace           = "SecurityDetection"
  statistic           = "Sum"
  period              = 1800
  threshold           = 30
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.eni_discovery_alerts.arn]
}

# Step 4: SNS topic policy (scoped to account)
data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.eni_discovery_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchAlarms"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.eni_discovery_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}""",
                alert_severity="medium",
                alert_title="Network Interface Enumeration Detected",
                alert_description_template="High volume of network interface enumeration from {userIdentity.arn}.",
                investigation_steps=[
                    "Identify the enumerating principal",
                    "Check if authorised network scanning",
                    "Review which network interfaces were queried",
                    "Look for follow-on exploitation attempts",
                ],
                containment_actions=[
                    "Review principal's IAM permissions",
                    "Monitor for lateral movement",
                    "Enable VPC Flow Logs",
                    "Audit security group changes",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist network monitoring tools and load balancer health checks",
            detection_coverage="70% - detects detailed interface enumeration",
            evasion_considerations="Slow enumeration below threshold",
            implementation_effort=EffortLevel.LOW,
            implementation_time="45 minutes",
            estimated_monthly_cost="$3-5",
            prerequisites=["CloudTrail logging to CloudWatch Logs"],
        ),
        # Strategy 3: GCP - Network Configuration Enumeration
        DetectionStrategy(
            strategy_id="t1016-gcp-network",
            name="GCP Network Configuration Discovery Detection",
            description="Detect enumeration of VPCs, subnets, routes, and firewall rules in GCP.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName=~"(compute.networks.list|compute.subnetworks.list|compute.routes.list|compute.firewalls.list|compute.addresses.list|compute.forwardingRules.list|v1.compute.networks.get|v1.compute.subnetworks.get)"''',
                gcp_terraform_template="""# GCP: Detect network configuration discovery

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "network_discovery_email" {
  display_name = "Network Discovery Security Alerts"
  type         = "email"

  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric
resource "google_logging_metric" "network_discovery" {
  name   = "network-configuration-discovery"
  filter = <<-EOT
    protoPayload.methodName=~"(compute.networks.list|compute.subnetworks.list|compute.routes.list|compute.firewalls.list|compute.addresses.list|v1.compute.networks.get|v1.compute.subnetworks.get)"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
    labels {
      key         = "principal"
      value_type  = "STRING"
      description = "Principal performing network discovery"
    }
  }

  label_extractors = {
    "principal" = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "network_discovery" {
  display_name = "Network Configuration Discovery Detected"
  combiner     = "OR"

  conditions {
    display_name = "High volume of network discovery API calls"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.network_discovery.name}\" AND resource.type=\"audited_resource\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 40

      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.network_discovery_email.id]

  alert_strategy {
    auto_close = "86400s"
  }

  documentation {
    content   = "High volume of network configuration discovery API calls detected. Investigate the principal and verify if this is authorised scanning activity."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="medium",
                alert_title="GCP Network Configuration Discovery",
                alert_description_template="High volume of network configuration discovery calls detected in GCP project.",
                investigation_steps=[
                    "Identify the principal performing network enumeration",
                    "Verify if this is authorised security scanning or automation",
                    "Review which specific network resources were queried",
                    "Check for unusual access patterns or source locations",
                    "Look for follow-on lateral movement or resource access",
                    "Review audit logs for other suspicious activity",
                    "Verify source IP address and geolocation",
                ],
                containment_actions=[
                    "Review and restrict IAM permissions for compute.networks.* and compute.subnetworks.*",
                    "Monitor for subsequent lateral movement attempts",
                    "Enable VPC Flow Logs for network traffic monitoring",
                    "Audit recent firewall rule changes",
                    "Consider implementing IAM Conditions for network access",
                    "If unauthorised, revoke credentials and rotate keys",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Whitelist infrastructure automation, CSPM tools, Terraform/deployment pipelines, and monitoring solutions. Adjust threshold based on deployment frequency.",
            detection_coverage="75% - volume-based detection",
            evasion_considerations="Slow enumeration below detection threshold. Legitimate permissions make activity normal.",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-15",
            prerequisites=[
                "Cloud Audit Logs enabled",
                "Admin Activity and Data Access logs configured",
            ],
        ),
        # Strategy 4: GCP - VPC Peering and Interconnect Discovery
        DetectionStrategy(
            strategy_id="t1016-gcp-connectivity",
            name="GCP Network Connectivity Discovery",
            description="Detect enumeration of VPC peering, Cloud VPN, and interconnect configurations.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName=~"(compute.networks.listPeeringRoutes|v1.compute.vpnTunnels.list|v1.compute.interconnects.list|v1.compute.routers.list)"''',
                gcp_terraform_template="""# GCP: Detect network connectivity discovery

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "connectivity_alerts" {
  display_name = "Network Connectivity Discovery Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric
resource "google_logging_metric" "connectivity_discovery" {
  name   = "network-connectivity-discovery"
  filter = <<-EOT
    protoPayload.methodName=~"(compute.networks.listPeeringRoutes|v1.compute.vpnTunnels.list|v1.compute.interconnects.list|v1.compute.routers.list)"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "connectivity_discovery" {
  display_name = "Network Connectivity Discovery"
  combiner     = "OR"

  conditions {
    display_name = "VPC peering and interconnect enumeration"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.connectivity_discovery.name}\""
      duration        = "600s"
      comparison      = "COMPARISON_GT"
      threshold_value = 10

      aggregations {
        alignment_period = "600s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.connectivity_alerts.id]

  documentation {
    content = "Network connectivity configuration discovery detected. Review for authorised scanning."
  }
}""",
                alert_severity="medium",
                alert_title="GCP Network Connectivity Discovery",
                alert_description_template="VPC peering and interconnect enumeration detected.",
                investigation_steps=[
                    "Identify principal enumerating connectivity",
                    "Check if authorised network audit",
                    "Review peering relationships queried",
                    "Look for privilege escalation attempts",
                ],
                containment_actions=[
                    "Review IAM permissions for compute.networks.*",
                    "Monitor VPC peering changes",
                    "Audit interconnect configurations",
                    "Enable VPC Service Controls",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist network engineering tools and compliance scanners",
            detection_coverage="65% - focuses on connectivity enumeration",
            evasion_considerations="Low-frequency queries may not trigger alerts",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$8-12",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
    ],
    recommended_order=[
        "t1016-aws-network",
        "t1016-gcp-network",
        "t1016-aws-eni-metadata",
        "t1016-gcp-connectivity",
    ],
    total_effort_hours=3.75,
    coverage_improvement="+8% improvement for Discovery tactic",
)
