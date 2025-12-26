"""
T1011 - Exfiltration Over Other Network Medium

Adversaries exfiltrate data through alternative network channels (WiFi, Bluetooth, cellular, RF)
rather than primary command and control connections.
Used in targeted espionage and air-gapped environment attacks.
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
    technique_id="T1011",
    technique_name="Exfiltration Over Other Network Medium",
    tactic_ids=["TA0010"],
    mitre_url="https://attack.mitre.org/techniques/T1011/",
    threat_context=ThreatContext(
        description=(
            "Adversaries leverage alternate network mediums for data exfiltration instead of "
            "using the primary command and control network. If the C2 network is a wired Internet "
            "connection, exfiltration may occur over WiFi, Bluetooth, cellular data, modem, or "
            "other radio frequency (RF) channels. In cloud environments, this technique manifests "
            "when adversaries enable alternate network interfaces on compromised instances, use "
            "secondary network cards, or configure cellular/wireless connections to bypass network "
            "monitoring on the primary interface. These alternative channels typically lack the "
            "same security monitoring as primary enterprise networks, making detection more difficult."
        ),
        attacker_goal="Exfiltrate data through alternative network channels to evade primary network monitoring and security controls",
        why_technique=[
            "Alternative channels bypass primary network monitoring",
            "Secondary interfaces often lack security controls",
            "Difficult to detect without comprehensive network visibility",
            "Can circumvent air-gapped network protections",
            "Wireless connections may be less monitored than wired",
            "Enables covert data transfer in high-security environments",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="rare",
        trend="stable",
        severity_score=8,
        severity_reasoning=(
            "Exfiltration over other network mediums represents a sophisticated threat typically "
            "employed by advanced adversaries targeting high-value environments. Whilst less common "
            "than standard exfiltration methods, the technique is highly effective at bypassing "
            "network security controls and monitoring systems. The ability to exfiltrate data through "
            "unmonitored channels poses significant risks to organisations with sensitive data, "
            "particularly those in defence, government, and critical infrastructure sectors. In cloud "
            "environments, the presence of secondary network interfaces or wireless capabilities on "
            "compute instances may indicate preparation for this technique."
        ),
        business_impact=[
            "Loss of sensitive or classified data through unmonitored channels",
            "Bypass of air-gap protections and network isolation",
            "Intellectual property theft from high-security environments",
            "Regulatory violations and compliance breaches",
            "Reputational damage from sophisticated security breach",
        ],
        typical_attack_phase="exfiltration",
        often_precedes=[],
        often_follows=["T1074", "T1560", "T1005", "T1105"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1011-aws-network-interface",
            name="AWS Secondary Network Interface Detection",
            description="Detect creation or attachment of additional network interfaces on EC2 instances that may enable alternative exfiltration channels.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.arn, eventName, requestParameters.networkInterfaceId, requestParameters.instanceId
| filter eventName in ["CreateNetworkInterface", "AttachNetworkInterface", "ModifyNetworkInterfaceAttribute"]
| filter requestParameters.instanceId != ""
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect secondary network interface creation for potential alternate exfiltration

Parameters:
  AlertEmail:
    Type: String
    Description: Email address for security alerts

Resources:
  # Step 1: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: Network Interface Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: EventBridge rule for network interface changes
  NetworkInterfaceRule:
    Type: AWS::Events::Rule
    Properties:
      Name: secondary-network-interface-detection
      Description: Detect secondary network interface creation
      EventPattern:
        source: [aws.ec2]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName:
            - CreateNetworkInterface
            - AttachNetworkInterface
            - ModifyNetworkInterfaceAttribute
      State: ENABLED
      Targets:
        - Id: AlertTarget
          Arn: !Ref AlertTopic
          RetryPolicy:
            MaximumEventAgeInSeconds: 3600
            MaximumRetryAttempts: 8
          DeadLetterConfig:
            Arn: !GetAtt DeadLetterQueue.Arn
          InputTransformer:
            InputPathsMap:
              account: $.account
              region: $.region
              time: $.time
              eventName: $.detail.eventName
              instanceId: $.detail.requestParameters.instanceId
              networkInterfaceId: $.detail.requestParameters.networkInterfaceId
              user: $.detail.userIdentity.arn
            InputTemplate: |
              "Network Interface Alert (T1011)
              time=<time> account=<account> region=<region>
              event=<eventName> instance=<instanceId>
              networkInterface=<networkInterfaceId>
              user=<user>
              Action: Investigate alternative exfiltration channel"

  # Step 3: Dead letter queue for failed deliveries
  DeadLetterQueue:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: network-interface-dlq
      MessageRetentionPeriod: 1209600

  # Step 4: SNS topic policy (scoped)
  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref AlertTopic]
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Sid: AllowEventBridgePublish
            Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn: !GetAtt NetworkInterfaceRule.Arn""",
                terraform_template="""# Detect secondary network interface creation

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "network_interface_alerts" {
  name         = "network-interface-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "Network Interface Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.network_interface_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule for network interface changes
resource "aws_cloudwatch_event_rule" "network_interface" {
  name        = "secondary-network-interface-detection"
  description = "Detect secondary network interface creation"

  event_pattern = jsonencode({
    source      = ["aws.ec2"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "CreateNetworkInterface",
        "AttachNetworkInterface",
        "ModifyNetworkInterfaceAttribute"
      ]
    }
  })
}

# Step 3: Dead letter queue for failed deliveries
resource "aws_sqs_queue" "dlq" {
  name                      = "network-interface-dlq"
  message_retention_seconds = 1209600
}

# Step 4: EventBridge target with DLQ, retry, and input transformer
resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.network_interface.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.network_interface_alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
  }

  input_transformer {
    input_paths = {
      account            = "$.account"
      region             = "$.region"
      time               = "$.time"
      eventName          = "$.detail.eventName"
      instanceId         = "$.detail.requestParameters.instanceId"
      networkInterfaceId = "$.detail.requestParameters.networkInterfaceId"
      user               = "$.detail.userIdentity.arn"
    }
    input_template = <<-EOT
"Network Interface Alert (T1011)
time=<time> account=<account> region=<region>
event=<eventName> instance=<instanceId>
networkInterface=<networkInterfaceId>
user=<user>
Action: Investigate alternative exfiltration channel"
EOT
  }
}

# Step 5: SNS topic policy (scoped to account and rule)
data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_events" {
  arn = aws_sns_topic.network_interface_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowEventBridgePublishScoped"
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.network_interface_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.network_interface.arn
        }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="Secondary Network Interface Created or Modified",
                alert_description_template="Network interface {networkInterfaceId} created/attached to instance {instanceId} by {userIdentity.arn}. May enable alternative exfiltration channel.",
                investigation_steps=[
                    "Identify the EC2 instance and its purpose",
                    "Review network interface configuration and subnet",
                    "Check if multiple network interfaces are business-required",
                    "Examine instance security groups and routing tables",
                    "Review VPC Flow Logs for traffic patterns on new interface",
                    "Verify authorisation for network configuration changes",
                    "Check for recent suspicious activity on the instance",
                ],
                containment_actions=[
                    "Detach unauthorised network interfaces immediately",
                    "Review and restrict ec2:CreateNetworkInterface permissions",
                    "Enable VPC Flow Logs on all network interfaces",
                    "Implement SCPs to prevent unauthorised network changes",
                    "Isolate affected instances for forensic analysis",
                    "Review security group rules for secondary interfaces",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known multi-homed instances, NAT instances, and network appliances. Exclude infrastructure deployment automation.",
            detection_coverage="80% - catches secondary interface creation",
            evasion_considerations="Attackers may use pre-existing interfaces or modify during initial provisioning",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled with EC2 data events"],
        ),
        DetectionStrategy(
            strategy_id="t1011-aws-unusual-traffic",
            name="AWS Unusual Network Interface Traffic Pattern",
            description="Detect traffic patterns on secondary network interfaces that may indicate alternative exfiltration channels.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, interfaceId, srcAddr, dstAddr, bytes, protocol, action
| filter action = "ACCEPT"
| stats sum(bytes) as total_bytes, count(*) as connection_count by interfaceId, bin(5m)
| filter total_bytes > 104857600
| sort total_bytes desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Monitor traffic patterns on network interfaces for exfiltration

Parameters:
  AlertEmail:
    Type: String
  VPCFlowLogGroup:
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

  # Step 2: Metric filter for large transfers
  LargeTransferFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref VPCFlowLogGroup
      FilterPattern: '[version, account, eni, source, destination, srcport, dstport, protocol, packets, bytes > 100000000, ...]'
      MetricTransformations:
        - MetricName: LargeNetworkTransfer
          MetricNamespace: Security
          MetricValue: "$bytes"
          Unit: Bytes

  # Step 3: CloudWatch alarm for large transfers
  LargeTransferAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: Unusual-Network-Interface-Traffic
      MetricName: LargeNetworkTransfer
      Namespace: Security
      Statistic: Sum
      Period: 300
      Threshold: 104857600
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching
      AlarmActions: [!Ref AlertTopic]

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
            Resource: !Ref AlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
      Topics:
        - !Ref AlertTopic""",
                terraform_template="""# Monitor network interface traffic patterns

variable "alert_email" {
  type = string
}

variable "vpc_flow_log_group" {
  type = string
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "traffic_alerts" {
  name = "network-traffic-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.traffic_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for large transfers
resource "aws_cloudwatch_log_metric_filter" "large_transfer" {
  name           = "large-network-transfer"
  log_group_name = var.vpc_flow_log_group
  pattern        = "[version, account, eni, source, destination, srcport, dstport, protocol, packets, bytes > 100000000, ...]"

  metric_transformation {
    name      = "LargeNetworkTransfer"
    namespace = "Security"
    value     = "$bytes"
    unit      = "Bytes"
  }
}

# Step 3: CloudWatch alarm for large transfers
resource "aws_cloudwatch_metric_alarm" "large_transfer" {
  alarm_name          = "Unusual-Network-Interface-Traffic"
  metric_name         = "LargeNetworkTransfer"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 104857600
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.traffic_alerts.arn]
}

# Step 4: SNS topic policy (scoped to account)
data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.traffic_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchAlarms"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.traffic_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="Unusual Network Interface Traffic Detected",
                alert_description_template="Large data transfer ({total_bytes} bytes) detected on network interface {interfaceId}.",
                investigation_steps=[
                    "Identify the instance associated with the network interface",
                    "Review traffic destinations and protocols used",
                    "Check if traffic pattern aligns with legitimate usage",
                    "Examine other network interfaces on the same instance",
                    "Review instance security configuration and recent changes",
                    "Correlate with CloudTrail events for suspicious activities",
                    "Check for data staging activities on the instance",
                ],
                containment_actions=[
                    "Modify security groups to block suspicious traffic",
                    "Detach secondary network interfaces if unauthorised",
                    "Isolate affected instance from network",
                    "Enable enhanced VPC Flow Logs monitoring",
                    "Implement network ACLs to restrict traffic",
                    "Review and update routing tables",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known data transfer workflows, backup operations, and legitimate high-bandwidth applications. Adjust byte thresholds based on environment.",
            detection_coverage="70% - catches large transfers on network interfaces",
            evasion_considerations="Low and slow exfiltration, encryption, or traffic mimicking legitimate patterns may evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-25",
            prerequisites=["VPC Flow Logs enabled on all interfaces"],
        ),
        DetectionStrategy(
            strategy_id="t1011-aws-network-mgmt",
            name="AWS Network Management Tool Execution Detection",
            description="Detect execution of network management commands that may enable alternative network interfaces.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.principalId, commandInvoked, instanceId
| filter commandInvoked like /rfkill|nmcli|iw|hcitool|networksetup|blueutil|ifconfig|ip link/
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect network management tool execution for alternative interfaces

Parameters:
  AlertEmail:
    Type: String
  SSMLogGroup:
    Type: String
    Description: CloudWatch log group for SSM command outputs

Resources:
  # Step 1: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter for network management commands
  NetworkToolFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref SSMLogGroup
      FilterPattern: '[time, request_id, command_id, instance, output = *rfkill* || output = *nmcli* || output = *hcitool* || output = *networksetup* || output = *blueutil*]'
      MetricTransformations:
        - MetricName: NetworkManagementToolExecution
          MetricNamespace: Security
          MetricValue: "1"

  # Step 3: CloudWatch alarm
  NetworkToolAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: Network-Management-Tool-Execution
      MetricName: NetworkManagementToolExecution
      Namespace: Security
      Statistic: Sum
      Period: 300
      Threshold: 1
      ComparisonOperator: GreaterThanOrEqualToThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching
      AlarmActions: [!Ref AlertTopic]

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
            Resource: !Ref AlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
      Topics:
        - !Ref AlertTopic""",
                terraform_template="""# Detect network management tool execution

variable "alert_email" {
  type = string
}

variable "ssm_log_group" {
  type        = string
  description = "CloudWatch log group for SSM command outputs"
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "network_tool_alerts" {
  name = "network-tool-execution-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.network_tool_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for network management commands
resource "aws_cloudwatch_log_metric_filter" "network_tools" {
  name           = "network-management-tools"
  log_group_name = var.ssm_log_group
  pattern        = "[time, request_id, command_id, instance, output = *rfkill* || output = *nmcli* || output = *hcitool* || output = *networksetup* || output = *blueutil*]"

  metric_transformation {
    name      = "NetworkManagementToolExecution"
    namespace = "Security"
    value     = "1"
  }
}

# Step 3: CloudWatch alarm
resource "aws_cloudwatch_metric_alarm" "network_tools" {
  alarm_name          = "Network-Management-Tool-Execution"
  metric_name         = "NetworkManagementToolExecution"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.network_tool_alerts.arn]
}

# Step 4: SNS topic policy (scoped to account)
data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.network_tool_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchAlarms"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.network_tool_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}""",
                alert_severity="medium",
                alert_title="Network Management Tool Execution Detected",
                alert_description_template="Network management tool executed on instance {instanceId}: {commandInvoked}. May indicate preparation for alternative network exfiltration.",
                investigation_steps=[
                    "Identify which user or role executed the command",
                    "Review command output and results",
                    "Check for subsequent network configuration changes",
                    "Examine instance for additional suspicious activities",
                    "Review CloudTrail for related API calls",
                    "Verify if network changes are authorised",
                    "Check for data transfer activities following command execution",
                ],
                containment_actions=[
                    "Restrict SSM access to prevent unauthorised commands",
                    "Review and limit instance profile permissions",
                    "Disable unnecessary network interfaces",
                    "Implement Systems Manager Session Manager logging",
                    "Create SCPs to prevent sensitive network commands",
                    "Enable enhanced CloudWatch logging",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Whitelist authorised network administrators and automated configuration management tools. Focus on unexpected command execution contexts.",
            detection_coverage="60% - catches network tool usage",
            evasion_considerations="Attackers may use alternative methods to configure network interfaces or execute commands outside of monitored channels",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$15-30",
            prerequisites=[
                "SSM Session Manager enabled",
                "CloudWatch Logs for SSM enabled",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1011-gcp-network-interface",
            name="GCP Secondary Network Interface Detection",
            description="Detect creation or modification of additional network interfaces on Compute Engine instances.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gce_instance"
(protoPayload.methodName="v1.compute.instances.insert"
OR protoPayload.methodName="v1.compute.instances.updateNetworkInterface"
OR protoPayload.methodName="v1.compute.instances.addAccessConfig")
protoPayload.serviceName="compute.googleapis.com"''',
                gcp_terraform_template="""# GCP: Detect secondary network interface creation

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: Notification channel for alerts
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alert Email"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for network interface changes
resource "google_logging_metric" "network_interface" {
  name   = "secondary-network-interface-changes"
  filter = <<-EOT
    resource.type="gce_instance"
    protoPayload.serviceName="compute.googleapis.com"
    (protoPayload.methodName="v1.compute.instances.insert" OR
     protoPayload.methodName="v1.compute.instances.updateNetworkInterface" OR
     protoPayload.methodName="v1.compute.instances.addAccessConfig")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "instance_name"
      value_type  = "STRING"
      description = "Compute Engine instance name"
    }
  }

  label_extractors = {
    "instance_name" = "EXTRACT(resource.labels.instance_id)"
  }
}

# Step 3: Alert policy for network interface changes
resource "google_monitoring_alert_policy" "network_interface_alert" {
  display_name = "Secondary Network Interface Detected"
  combiner     = "OR"

  conditions {
    display_name = "Network interface created or modified"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.network_interface.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "1800s"
  }
}""",
                alert_severity="high",
                alert_title="GCP: Secondary Network Interface Created or Modified",
                alert_description_template="Network interface created/modified on instance {instance_name}. May enable alternative exfiltration channel.",
                investigation_steps=[
                    "Identify the Compute Engine instance and its purpose",
                    "Review network interface configuration and VPC",
                    "Check if multiple network interfaces are required",
                    "Examine firewall rules for the new interface",
                    "Review VPC Flow Logs for traffic patterns",
                    "Verify authorisation for network changes",
                    "Check instance for recent suspicious activities",
                ],
                containment_actions=[
                    "Remove unauthorised network interfaces",
                    "Review and restrict compute.instances.updateNetworkInterface permissions",
                    "Enable VPC Flow Logs on all network interfaces",
                    "Implement organisation policies for network restrictions",
                    "Isolate affected instances for investigation",
                    "Review firewall rules for secondary interfaces",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known multi-interface instances and network appliances. Exclude infrastructure automation tools.",
            detection_coverage="80% - catches secondary interface creation",
            evasion_considerations="Attackers may configure interfaces during initial deployment or use existing interfaces",
            implementation_effort=EffortLevel.LOW,
            implementation_time="45 minutes",
            estimated_monthly_cost="$8-15",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1011-gcp-traffic-pattern",
            name="GCP Unusual VPC Flow Pattern Detection",
            description="Detect unusual traffic patterns that may indicate data exfiltration through alternative network channels.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_subnetwork"
jsonPayload.connection.dest_ip!=""
jsonPayload.bytes_sent > 104857600""",
                gcp_terraform_template="""# GCP: Detect unusual VPC flow patterns

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alert Email"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for large transfers
resource "google_logging_metric" "large_transfer" {
  name   = "unusual-network-transfer"
  filter = <<-EOT
    resource.type="gce_subnetwork"
    jsonPayload.connection.dest_ip!=""
    jsonPayload.bytes_sent > 104857600
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
  }
}

# Step 3: Alert policy for large transfers
resource "google_monitoring_alert_policy" "large_transfer_alert" {
  display_name = "Unusual Network Traffic Pattern Detected"
  combiner     = "OR"

  conditions {
    display_name = "Large data transfer detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.large_transfer.name}\""
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
    auto_close = "1800s"
  }
}""",
                alert_severity="high",
                alert_title="GCP: Unusual Network Traffic Pattern Detected",
                alert_description_template="Large data transfer detected through VPC. May indicate alternative exfiltration channel usage.",
                investigation_steps=[
                    "Identify source and destination of traffic",
                    "Review instance network configuration",
                    "Check for multiple network interfaces on source instance",
                    "Examine traffic protocols and destinations",
                    "Review Cloud Audit Logs for network changes",
                    "Verify legitimacy of data transfer",
                    "Check for data staging activities",
                ],
                containment_actions=[
                    "Update firewall rules to block suspicious traffic",
                    "Remove unauthorised network interfaces",
                    "Isolate affected instances",
                    "Enable enhanced VPC Flow Logs",
                    "Implement VPC Service Controls",
                    "Review and update network policies",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known data transfer workflows and backup operations. Adjust byte thresholds for environment.",
            detection_coverage="70% - catches large network transfers",
            evasion_considerations="Low-volume or encrypted exfiltration may evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["VPC Flow Logs enabled on subnets"],
        ),
    ],
    recommended_order=[
        "t1011-aws-network-interface",
        "t1011-gcp-network-interface",
        "t1011-aws-unusual-traffic",
        "t1011-gcp-traffic-pattern",
        "t1011-aws-network-mgmt",
    ],
    total_effort_hours=6.0,
    coverage_improvement="+15% improvement for Exfiltration tactic detection",
)
