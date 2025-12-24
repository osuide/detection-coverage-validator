"""
T1018 - Remote System Discovery

Adversaries attempt to identify other systems on a network using various discovery
techniques including network enumeration tools, directory services queries, and
cloud API calls to map infrastructure and identify lateral movement targets.
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
    technique_id="T1018",
    technique_name="Remote System Discovery",
    tactic_ids=["TA0007"],  # Discovery
    mitre_url="https://attack.mitre.org/techniques/T1018/",
    threat_context=ThreatContext(
        description=(
            "Adversaries attempt to identify other systems on a network to map the environment "
            "and identify targets for lateral movement. Traditional methods include using native "
            "utilities like 'net view', 'ping', 'arp', and directory service queries. In cloud "
            "environments, attackers enumerate EC2 instances, GCE instances, and container hosts "
            "using cloud APIs. This reconnaissance activity helps adversaries understand network "
            "topology, identify high-value targets, and plan lateral movement paths across the infrastructure."
        ),
        attacker_goal="Map remote systems and network topology to identify lateral movement targets and high-value assets",
        why_technique=[
            "Identifies potential lateral movement targets",
            "Maps network topology and system relationships",
            "Discovers domain controllers and critical infrastructure",
            "Locates systems with specific roles or data",
            "Enables targeted attacks on high-value assets",
            "Reveals system naming conventions and architecture patterns",
        ],
        known_threat_actors=[],
        recent_campaigns=[
            Campaign(
                name="SolarWinds Compromise (C0024)",
                year=2020,
                description="APT29 used AdFind to enumerate remote systems and Active Directory computers, identifying targets for lateral movement across compromised networks",
                reference_url="https://attack.mitre.org/campaigns/C0024/",
            ),
            Campaign(
                name="2015 Ukraine Electric Power Attack (C0028)",
                year=2015,
                description="Sandworm Team discovered OT systems visible from IT networks using network enumeration tools, enabling targeted attacks on critical infrastructure",
                reference_url="https://attack.mitre.org/campaigns/C0028/",
            ),
            Campaign(
                name="Operation Wocao (C0014)",
                year=2019,
                description="Threat actors used nbtscan and ping commands to systematically discover remote systems during multi-stage attacks on managed service providers",
                reference_url="https://attack.mitre.org/campaigns/C0014/",
            ),
        ],
        prevalence="very_common",
        trend="increasing",
        severity_score=5,
        severity_reasoning=(
            "Remote system discovery is a standard post-compromise reconnaissance technique "
            "that indicates active threat actor presence. Whilst not directly damaging, it's "
            "a critical precursor to lateral movement and targeted attacks. Common across all "
            "threat actor types including ransomware operators and APT groups. Moderate severity "
            "due to its role in attack progression and high prevalence in breaches."
        ),
        business_impact=[
            "Reveals network architecture and system inventory",
            "Indicates active post-compromise reconnaissance",
            "Precursor to lateral movement attempts",
            "Exposes critical infrastructure and high-value targets",
            "Early warning of credential compromise",
            "May reveal inadequate network segmentation",
        ],
        typical_attack_phase="discovery",
        often_precedes=["T1021", "T1570", "T1210", "T1003"],
        often_follows=["T1078.004", "T1059.009", "T1110", "T1190"],
    ),
    detection_strategies=[
        # Strategy 1: AWS - EC2 Instance Enumeration
        DetectionStrategy(
            strategy_id="t1018-aws-instance-enum",
            name="AWS EC2 Instance Discovery Detection",
            description="Detect enumeration of EC2 instances, tags, and metadata indicating reconnaissance of remote systems in AWS environments.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, userIdentity.arn, sourceIPAddress, requestParameters
| filter eventName in ["DescribeInstances", "DescribeInstanceAttribute", "DescribeInstanceStatus", "DescribeTags", "GetConsoleOutput"]
| stats count(*) as instance_enum_count by userIdentity.arn, bin(1h)
| filter instance_enum_count > 40
| sort instance_enum_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect remote system discovery via EC2 instance enumeration

Parameters:
  CloudTrailLogGroup:
    Type: String
    Description: CloudWatch Logs group receiving CloudTrail events
  AlertEmail:
    Type: String
    Description: Email address for security alerts

Resources:
  # Step 1: SNS topic for alerts
  InstanceDiscoveryAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: EC2 Instance Discovery Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter for instance discovery
  InstanceDiscoveryFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventName = "DescribeInstances" || $.eventName = "DescribeInstanceAttribute" || $.eventName = "DescribeInstanceStatus" || $.eventName = "DescribeTags") }'
      MetricTransformations:
        - MetricName: EC2InstanceDiscovery
          MetricNamespace: SecurityDetection
          MetricValue: "1"
          DefaultValue: 0

  # Step 3: CloudWatch alarm for suspicious volume
  InstanceDiscoveryAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: EC2InstanceDiscoveryDetected
      AlarmDescription: High volume of EC2 instance enumeration API calls detected
      MetricName: EC2InstanceDiscovery
      Namespace: SecurityDetection
      Statistic: Sum
      Period: 3600
      Threshold: 50
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      AlarmActions:
        - !Ref InstanceDiscoveryAlertTopic
      TreatMissingData: notBreaching""",
                terraform_template="""# AWS: Detect remote system discovery via EC2 enumeration

variable "cloudtrail_log_group" {
  type        = string
  description = "CloudWatch Logs group receiving CloudTrail events"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "instance_discovery_alerts" {
  name         = "ec2-instance-discovery-alerts"
  display_name = "EC2 Instance Discovery Alerts"
}

resource "aws_sns_topic_subscription" "email_alerts" {
  topic_arn = aws_sns_topic.instance_discovery_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for instance discovery
resource "aws_cloudwatch_log_metric_filter" "instance_discovery" {
  name           = "ec2-instance-discovery"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventName = \"DescribeInstances\" || $.eventName = \"DescribeInstanceAttribute\" || $.eventName = \"DescribeInstanceStatus\" || $.eventName = \"DescribeTags\") }"

  metric_transformation {
    name          = "EC2InstanceDiscovery"
    namespace     = "SecurityDetection"
    value         = "1"
    default_value = 0
  }
}

# Step 3: CloudWatch alarm for suspicious volume
resource "aws_cloudwatch_metric_alarm" "instance_discovery" {
  alarm_name          = "EC2InstanceDiscoveryDetected"
  alarm_description   = "High volume of EC2 instance enumeration API calls detected"
  metric_name         = "EC2InstanceDiscovery"
  namespace           = "SecurityDetection"
  statistic           = "Sum"
  period              = 3600
  threshold           = 50
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.instance_discovery_alerts.arn]
  treat_missing_data  = "notBreaching"
}""",
                alert_severity="medium",
                alert_title="EC2 Instance Discovery Activity Detected",
                alert_description_template="High volume of EC2 instance discovery API calls from {userIdentity.arn}. {instance_enum_count} enumeration calls in 1 hour may indicate remote system reconnaissance.",
                investigation_steps=[
                    "Identify the principal performing EC2 instance enumeration",
                    "Verify if this is authorised security scanning or infrastructure automation",
                    "Review the source IP address and geolocation for anomalies",
                    "Check CloudTrail for other suspicious discovery activities",
                    "Examine instance tags and filters used in enumeration queries",
                    "Look for follow-on lateral movement or instance access attempts",
                    "Review recent authentication activity for the principal",
                ],
                containment_actions=[
                    "Review and restrict IAM permissions for ec2:Describe* actions",
                    "Monitor for subsequent lateral movement or Systems Manager usage",
                    "Consider implementing IAM condition keys requiring MFA",
                    "Enable VPC Flow Logs to track network-level discovery attempts",
                    "Audit Session Manager and EC2 Instance Connect activity",
                    "If unauthorised, rotate compromised credentials immediately",
                    "Review EC2 instance metadata service usage (IMDSv2)",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Whitelist infrastructure automation tools, AWS Config, Systems Manager Fleet Manager, CSPM scanners, monitoring solutions, and DevOps CI/CD pipelines. Adjust threshold based on environment size.",
            detection_coverage="80% - volume-based detection covers bulk instance enumeration",
            evasion_considerations="Slow, throttled enumeration below threshold evades detection. Legitimate IAM permissions make activity appear normal. Instance metadata service access not covered.",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=[
                "CloudTrail logging to CloudWatch Logs",
                "EC2 read events logged",
            ],
        ),
        # Strategy 2: AWS - Systems Manager Remote Command Execution
        DetectionStrategy(
            strategy_id="t1018-aws-ssm-discovery",
            name="AWS Systems Manager Discovery Commands",
            description="Detect use of Systems Manager to execute remote discovery commands like 'net view', 'ping', 'arp', or 'hostname' across multiple instances.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, userIdentity.arn, requestParameters.commands, requestParameters.instanceIds
| filter eventName = "SendCommand"
| filter requestParameters.commands like /net view|ping|arp|hostname|nltest|nbtstat|dsquery|AdFind/
| stats count(*) as discovery_commands by userIdentity.arn, bin(30m)
| sort discovery_commands desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect remote system discovery via Systems Manager commands

Parameters:
  CloudTrailLogGroup:
    Type: String
  AlertEmail:
    Type: String

Resources:
  # Step 1: SNS topic
  SSMDiscoveryAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter
  SSMDiscoveryFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventName = "SendCommand") && (($.requestParameters.commands = "*net view*") || ($.requestParameters.commands = "*ping*") || ($.requestParameters.commands = "*arp*") || ($.requestParameters.commands = "*nltest*")) }'
      MetricTransformations:
        - MetricName: SSMDiscoveryCommands
          MetricNamespace: SecurityDetection
          MetricValue: "1"

  # Step 3: Alarm
  SSMDiscoveryAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: SSMRemoteDiscoveryDetected
      MetricName: SSMDiscoveryCommands
      Namespace: SecurityDetection
      Statistic: Sum
      Period: 1800
      Threshold: 5
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      AlarmActions: [!Ref SSMDiscoveryAlertTopic]""",
                terraform_template="""# AWS: Detect remote discovery via Systems Manager

variable "cloudtrail_log_group" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "ssm_discovery_alerts" {
  name = "ssm-remote-discovery-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.ssm_discovery_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter
resource "aws_cloudwatch_log_metric_filter" "ssm_discovery" {
  name           = "ssm-remote-discovery-commands"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventName = \"SendCommand\") && (($.requestParameters.commands = \"*net view*\") || ($.requestParameters.commands = \"*ping*\") || ($.requestParameters.commands = \"*arp*\") || ($.requestParameters.commands = \"*nltest*\")) }"

  metric_transformation {
    name      = "SSMDiscoveryCommands"
    namespace = "SecurityDetection"
    value     = "1"
  }
}

# Step 3: Alarm
resource "aws_cloudwatch_metric_alarm" "ssm_discovery" {
  alarm_name          = "SSMRemoteDiscoveryDetected"
  alarm_description   = "Remote system discovery commands executed via Systems Manager"
  metric_name         = "SSMDiscoveryCommands"
  namespace           = "SecurityDetection"
  statistic           = "Sum"
  period              = 1800
  threshold           = 5
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.ssm_discovery_alerts.arn]
}""",
                alert_severity="high",
                alert_title="Remote Discovery Commands via Systems Manager",
                alert_description_template="Remote system discovery commands executed via Systems Manager by {userIdentity.arn}. Commands detected: {requestParameters.commands}",
                investigation_steps=[
                    "Identify the principal executing remote commands",
                    "Review the specific commands executed and target instances",
                    "Check if this is authorised systems administration or security testing",
                    "Examine Systems Manager command history and outputs",
                    "Look for patterns of reconnaissance across multiple instances",
                    "Review recent authentication and access patterns",
                    "Check for data exfiltration attempts following discovery",
                ],
                containment_actions=[
                    "Review IAM permissions for ssm:SendCommand",
                    "Enable Systems Manager Session Manager logging to S3",
                    "Implement Session Manager run-as restrictions",
                    "Monitor for lateral movement attempts",
                    "Review and restrict SSM managed instance permissions",
                    "Consider implementing AWS Config rules for SSM compliance",
                    "If unauthorised, isolate affected instances and rotate credentials",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist authorised administrative runbooks and approved systems management activities. Low false positives as network discovery commands are rarely legitimate.",
            detection_coverage="70% - detects common discovery commands but not all possible variations",
            evasion_considerations="Obfuscated commands, PowerShell-based discovery, or custom scripts may evade pattern matching",
            implementation_effort=EffortLevel.LOW,
            implementation_time="45 minutes",
            estimated_monthly_cost="$3-5",
            prerequisites=[
                "CloudTrail logging to CloudWatch Logs",
                "Systems Manager in use",
            ],
        ),
        # Strategy 3: GCP - Compute Instance Enumeration
        DetectionStrategy(
            strategy_id="t1018-gcp-instance-enum",
            name="GCP Compute Instance Discovery Detection",
            description="Detect enumeration of GCE instances, instance groups, and metadata indicating remote system reconnaissance in GCP.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.serviceName="compute.googleapis.com"
protoPayload.methodName=~"(v1.compute.instances.list|v1.compute.instances.get|v1.compute.instances.aggregatedList|beta.compute.instanceGroupManagers.list|v1.compute.zones.list)"''',
                gcp_terraform_template="""# GCP: Detect remote system discovery via instance enumeration

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "instance_discovery_email" {
  display_name = "Instance Discovery Security Alerts"
  type         = "email"

  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric
resource "google_logging_metric" "instance_discovery" {
  name   = "compute-instance-discovery"
  filter = <<-EOT
    protoPayload.serviceName="compute.googleapis.com"
    protoPayload.methodName=~"(v1.compute.instances.list|v1.compute.instances.get|v1.compute.instances.aggregatedList|beta.compute.instanceGroupManagers.list|v1.compute.zones.list)"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
    labels {
      key         = "principal"
      value_type  = "STRING"
      description = "Principal performing instance discovery"
    }
  }

  label_extractors = {
    "principal" = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "instance_discovery" {
  display_name = "Compute Instance Discovery Detected"
  combiner     = "OR"

  conditions {
    display_name = "High volume of instance discovery API calls"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.instance_discovery.name}\" AND resource.type=\"audited_resource\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 50

      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.instance_discovery_email.id]

  alert_strategy {
    auto_close = "86400s"
  }

  documentation {
    content   = "High volume of compute instance discovery API calls detected. Investigate the principal and verify if this is authorised scanning or automation."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="medium",
                alert_title="GCP Compute Instance Discovery",
                alert_description_template="High volume of compute instance discovery calls detected from principal {principal} in GCP project.",
                investigation_steps=[
                    "Identify the principal (user or service account) performing enumeration",
                    "Verify if this is authorised security scanning or infrastructure automation",
                    "Review the source IP address and geolocation",
                    "Check for unusual access patterns or timing",
                    "Look for follow-on SSH/RDP connection attempts to discovered instances",
                    "Review audit logs for other suspicious discovery activities",
                    "Examine service account key usage if applicable",
                ],
                containment_actions=[
                    "Review and restrict IAM permissions for compute.instances.list and compute.instances.get",
                    "Monitor for subsequent lateral movement via SSH or OS Login",
                    "Enable VPC Flow Logs for network-level discovery monitoring",
                    "Implement organisation policies to restrict instance enumeration",
                    "Audit recent changes to IAM bindings and service accounts",
                    "Consider implementing VPC Service Controls for data perimeter",
                    "If unauthorised, revoke service account keys and rotate credentials",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Whitelist infrastructure automation tools, GCP Config Connector, Terraform Cloud, CSPM scanners, and monitoring solutions. Adjust threshold based on deployment frequency and environment size.",
            detection_coverage="80% - volume-based detection covers bulk instance enumeration",
            evasion_considerations="Slow enumeration below threshold evades detection. Legitimate service account permissions make activity appear normal. Instance metadata API access not covered by this detection.",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-15",
            prerequisites=[
                "Cloud Audit Logs enabled",
                "Admin Activity and Data Access logs configured",
            ],
        ),
        # Strategy 4: GCP - OS Login and SSH Key Discovery
        DetectionStrategy(
            strategy_id="t1018-gcp-ssh-discovery",
            name="GCP SSH Access Pattern Discovery",
            description="Detect enumeration of SSH keys and OS Login configurations across instances, indicating preparation for remote system access.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""protoPayload.serviceName="compute.googleapis.com"
protoPayload.methodName=~"(beta.compute.instances.getIamPolicy|v1.compute.instances.getSerialPortOutput|beta.compute.projects.getXpnHost|oslogin)"
protoPayload.authorizationInfo.granted=true""",
                gcp_terraform_template="""# GCP: Detect SSH and OS Login discovery

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "ssh_discovery_alerts" {
  display_name = "SSH Access Discovery Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric
resource "google_logging_metric" "ssh_discovery" {
  name   = "ssh-access-pattern-discovery"
  filter = <<-EOT
    protoPayload.serviceName="compute.googleapis.com"
    protoPayload.methodName=~"(beta.compute.instances.getIamPolicy|v1.compute.instances.getSerialPortOutput|oslogin)"
    protoPayload.authorizationInfo.granted=true
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "ssh_discovery" {
  display_name = "SSH Access Pattern Discovery"
  combiner     = "OR"

  conditions {
    display_name = "Enumeration of SSH keys and OS Login configurations"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.ssh_discovery.name}\""
      duration        = "600s"
      comparison      = "COMPARISON_GT"
      threshold_value = 10

      aggregations {
        alignment_period   = "600s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.ssh_discovery_alerts.id]

  documentation {
    content = "SSH access pattern discovery detected. Review for authorised administrative activity or potential reconnaissance."
  }
}""",
                alert_severity="medium",
                alert_title="GCP SSH Access Pattern Discovery",
                alert_description_template="Enumeration of SSH keys and OS Login configurations detected, indicating remote access reconnaissance.",
                investigation_steps=[
                    "Identify the principal querying SSH and OS Login settings",
                    "Check if this is authorised security audit or administration",
                    "Review which instances were targeted",
                    "Look for subsequent SSH connection attempts",
                    "Examine OS Login and SSH key modifications",
                    "Check for IAM policy changes on instances",
                ],
                containment_actions=[
                    "Review IAM permissions for compute.instances.getIamPolicy",
                    "Monitor OS Login activity and SSH connections",
                    "Enable serial port access logging",
                    "Audit SSH keys across all instances",
                    "Implement organisation policies for OS Login enforcement",
                    "Consider requiring OS Login for all instances",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist authorised systems administration tools and compliance scanners. Threshold may need adjustment for larger environments.",
            detection_coverage="65% - focuses on SSH access preparation activities",
            evasion_considerations="Attackers may use existing authorised SSH keys without discovery. Direct instance access via compromised credentials may not trigger this detection.",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$8-12",
            prerequisites=[
                "Cloud Audit Logs enabled",
                "Data Access logs for Compute Engine",
            ],
        ),
    ],
    recommended_order=[
        "t1018-aws-instance-enum",
        "t1018-gcp-instance-enum",
        "t1018-aws-ssm-discovery",
        "t1018-gcp-ssh-discovery",
    ],
    total_effort_hours=3.75,
    coverage_improvement="+7% improvement for Discovery tactic",
)
