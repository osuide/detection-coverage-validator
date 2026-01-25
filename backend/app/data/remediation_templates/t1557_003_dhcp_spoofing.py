"""
T1557.003 - Adversary-in-the-Middle: DHCP Spoofing

Adversaries impersonate DHCP servers to redirect network traffic through attacker-controlled
systems, enabling credential theft and traffic interception. Used to capture unencrypted
credentials and manipulate DNS/gateway configurations.

IMPORTANT DETECTION LIMITATIONS:
VPC Flow Logs can see DHCP traffic (UDP ports 67/68) but CANNOT inspect packet contents
to distinguish legitimate DHCP servers from rogue ones.

What VPC Flow Logs CAN detect:
- Traffic on DHCP ports (67/68)
- Multiple sources responding on DHCP ports (potential rogue servers)
- Traffic volume anomalies

What VPC Flow Logs CANNOT detect:
- Whether DHCP offers are legitimate or malicious
- Actual DHCP configuration being offered
- Malicious DNS/gateway settings in offers

Coverage reality:
- VPC Flow Logs: ~30% (detects rogue DHCP server presence, not malicious config)
- CloudTrail DHCP Options monitoring: ~90% (detects infrastructure config changes)
- VPC Traffic Mirroring with packet inspection: ~70%

Best detection approach:
1. Monitor CloudTrail for DHCP Options Set changes (cloud API level - highly accurate)
2. VPC Flow Logs for unexpected DHCP server sources
3. Correlate with known authorised DHCP server IPs
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
    technique_id="T1557.003",
    technique_name="Adversary-in-the-Middle: DHCP Spoofing",
    tactic_ids=["TA0006", "TA0009"],  # Credential Access, Collection
    mitre_url="https://attack.mitre.org/techniques/T1557/003/",
    threat_context=ThreatContext(
        description=(
            "Adversaries impersonate DHCP servers to redirect network traffic through "
            "attacker-controlled systems. By responding to DHCP discovery messages with "
            "malicious offers containing attacker-controlled DNS servers or gateways, "
            "adversaries achieve a man-in-the-middle position to intercept communications "
            "and capture credentials transmitted over unencrypted protocols."
        ),
        attacker_goal="Redirect network traffic through attacker infrastructure to intercept credentials and data",
        why_technique=[
            "Capture credentials transmitted over network",
            "Redirect DNS queries to malicious servers",
            "Force traffic through attacker-controlled gateways",
            "Intercept API requests and cloud service traffic",
            "Perform denial-of-service via DHCP exhaustion",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="low",
        trend="stable",
        severity_score=8,
        severity_reasoning=(
            "Enables credential theft and complete traffic interception in cloud environments. "
            "Allows attackers to redirect all network communications through malicious infrastructure. "
            "Particularly dangerous for capturing cloud service credentials and API keys. "
            "Difficult to detect when performed within VPC networks or containerised environments."
        ),
        business_impact=[
            "Complete traffic interception and credential theft",
            "DNS poisoning and phishing attacks",
            "Session hijacking and unauthorised access",
            "Compliance violations from data interception",
            "Network denial-of-service from DHCP exhaustion",
        ],
        typical_attack_phase="credential_access",
        often_precedes=["T1078.004", "T1528", "T1550", "T1557"],
        often_follows=["T1190", "T1133", "T1078.004"],
    ),
    detection_strategies=[
        # Strategy 1: AWS - DHCP Options Set Monitoring
        DetectionStrategy(
            strategy_id="t1557-003-aws-dhcp",
            name="AWS VPC DHCP Options Monitoring",
            description="Detect unauthorised changes to VPC DHCP options that could redirect traffic.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.ec2"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventName": [
                            "CreateDhcpOptions",
                            "AssociateDhcpOptions",
                            "DeleteDhcpOptions",
                        ]
                    },
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect unauthorised DHCP options changes

Parameters:
  AlertEmail:
    Type: String
    Description: Email for alerts

Resources:
  # Step 1: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: EventBridge rule for DHCP operations
  DhcpOptionsRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.ec2]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName:
            - CreateDhcpOptions
            - AssociateDhcpOptions
            - DeleteDhcpOptions
      Targets:
        - Id: AlertTopic
          Arn: !Ref AlertTopic

  # Step 3: Topic policy to allow EventBridge
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
            Resource: !Ref AlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn: !GetAtt DhcpOptionsRule.Arn""",
                terraform_template="""# AWS: Monitor VPC DHCP options changes

variable "alert_email" {
  type        = string
  description = "Email for alerts"
}

variable "location" {
  type        = string
  description = "Azure region for resources"
  default     = "uksouth"
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "dhcp-options-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule for DHCP operations
resource "aws_cloudwatch_event_rule" "dhcp_options" {
  name = "dhcp-options-monitoring"
  event_pattern = jsonencode({
    source      = ["aws.ec2"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "CreateDhcpOptions",
        "AssociateDhcpOptions",
        "DeleteDhcpOptions"
      ]
    }
  })
}

# Dead Letter Queue for failed events
resource "aws_sqs_queue" "dlq" {
  name                      = "dhcp-options-dlq"
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
        ArnEquals = { "aws:SourceArn" = aws_cloudwatch_event_rule.dhcp_options.arn }
      }
    }]
  })
}

# EventBridge target with retry and DLQ
resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.dhcp_options.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
  }
  input_transformer {
    input_paths = {
      account       = "$.account"
      region        = "$.region"
      time          = "$.time"
      eventName     = "$.detail.eventName"
      eventSource   = "$.detail.eventSource"
      sourceIP      = "$.detail.sourceIPAddress"
      userIdentity  = "$.detail.userIdentity.arn"
    }

    input_template = <<-EOT
"CloudTrail Security Alert
Time: <time>
Account: <account>
Region: <region>
Event: <eventName>
Source: <eventSource>
User: <userIdentity>
Source IP: <sourceIP>
Action: Review CloudTrail event and investigate"
EOT
  }

}

# Step 3: SNS topic policy
data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_events" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.alerts.arn
    Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
          ArnEquals = {
            "aws:SourceArn" = [
              aws_cloudwatch_event_rule.dhcp_options.arn,
              aws_cloudwatch_event_rule.resolver_endpoint.arn,
            ]
          }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="VPC DHCP Options Modified",
                alert_description_template="DHCP options {eventName} performed on VPC {vpcId} by {userIdentity.principalId}. Potential traffic redirection attempt.",
                investigation_steps=[
                    "Verify the principal who performed the DHCP operation",
                    "Review the new DHCP options configuration (DNS servers, domain name, NTP servers)",
                    "Check if DNS servers point to known-good resolvers",
                    "Examine CloudTrail for related suspicious activities",
                    "Verify no unauthorised Route 53 Resolver endpoints created",
                    "Review VPC Flow Logs for traffic to unexpected DNS servers",
                ],
                containment_actions=[
                    "Revert to known-good DHCP options immediately",
                    "Revoke compromised IAM credentials",
                    "Review and restrict ec2:*DhcpOptions permissions",
                    "Enable SCPs to prevent DHCP option modifications",
                    "Force DNS resolution through Route 53 Resolver",
                    "Implement VPC endpoint policies for DNS traffic",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist authorised network operations and infrastructure automation",
            detection_coverage="95% - catches DHCP option changes via CloudTrail",
            evasion_considerations="Compromised admin credentials may appear legitimate; initial VPC setup may go undetected",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled"],
        ),
        # Strategy 2: AWS - Route 53 Resolver Endpoint Monitoring
        DetectionStrategy(
            strategy_id="t1557-003-aws-resolver",
            name="Route 53 Resolver Endpoint Detection",
            description="Detect creation of unauthorised Route 53 Resolver endpoints that could intercept DNS traffic.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.route53resolver"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventName": [
                            "CreateResolverEndpoint",
                            "UpdateResolverEndpoint",
                            "AssociateResolverEndpointIpAddress",
                        ]
                    },
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect unauthorised Route 53 Resolver endpoints

Parameters:
  AlertEmail:
    Type: String

Resources:
  # Step 1: SNS topic
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: EventBridge rule
  ResolverEndpointRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.route53resolver]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName:
            - CreateResolverEndpoint
            - UpdateResolverEndpoint
            - AssociateResolverEndpointIpAddress
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
            Resource: !Ref AlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn: !GetAtt ResolverEndpointRule.Arn""",
                terraform_template="""# AWS: Monitor Route 53 Resolver endpoints

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "resolver-endpoint-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule
resource "aws_cloudwatch_event_rule" "resolver_endpoint" {
  name = "resolver-endpoint-monitoring"
  event_pattern = jsonencode({
    source      = ["aws.route53resolver"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "CreateResolverEndpoint",
        "UpdateResolverEndpoint",
        "AssociateResolverEndpointIpAddress"
      ]
    }
  })
}

# Dead Letter Queue for Route 53 Resolver events
resource "aws_sqs_queue" "resolver_dlq" {
  name                      = "resolver-endpoint-dlq"
  message_retention_seconds = 1209600  # 14 days
}

resource "aws_sqs_queue_policy" "resolver_dlq" {
  queue_url = aws_sqs_queue.resolver_dlq.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.resolver_dlq.arn
      Condition = {
        ArnEquals = { "aws:SourceArn" = aws_cloudwatch_event_rule.resolver_endpoint.arn }
      }
    }]
  })
}

# EventBridge target with retry and DLQ
resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.resolver_endpoint.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.resolver_dlq.arn
  }
  input_transformer {
    input_paths = {
      account       = "$.account"
      region        = "$.region"
      time          = "$.time"
      eventName     = "$.detail.eventName"
      eventSource   = "$.detail.eventSource"
      sourceIP      = "$.detail.sourceIPAddress"
      userIdentity  = "$.detail.userIdentity.arn"
    }

    input_template = <<-EOT
"CloudTrail Security Alert
Time: <time>
Account: <account>
Region: <region>
Event: <eventName>
Source: <eventSource>
User: <userIdentity>
Source IP: <sourceIP>
Action: Review CloudTrail event and investigate"
EOT
  }

}

# Step 3: SNS topic policy
resource "aws_sns_topic_policy" "allow_events" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.alerts.arn
    Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
          ArnEquals = {
            "aws:SourceArn" = [
              aws_cloudwatch_event_rule.dhcp_options.arn,
              aws_cloudwatch_event_rule.resolver_endpoint.arn,
            ]
          }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="Route 53 Resolver Endpoint Modified",
                alert_description_template="Resolver endpoint {eventName} performed by {userIdentity.principalId}. Potential DNS interception attempt.",
                investigation_steps=[
                    "Verify the principal performing the resolver operation",
                    "Review the resolver endpoint configuration and IP addresses",
                    "Check if endpoint is in authorised VPC and subnets",
                    "Examine resolver rules associated with the endpoint",
                    "Review CloudTrail for related DNS configuration changes",
                    "Validate outbound resolver rules point to legitimate targets",
                ],
                containment_actions=[
                    "Delete unauthorised resolver endpoints immediately",
                    "Revoke compromised IAM credentials",
                    "Review and restrict route53resolver:* permissions",
                    "Enable SCPs to control resolver endpoint creation",
                    "Audit all resolver rules and endpoint associations",
                    "Enable DNSSEC validation on Route 53 Resolver",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist authorised DNS operations and hybrid DNS architectures",
            detection_coverage="90% - catches resolver endpoint operations",
            evasion_considerations="Legitimate hybrid DNS configurations may mask malicious endpoints",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled"],
        ),
        # Strategy 3: AWS - VPC Flow Logs for DHCP Traffic Analysis
        DetectionStrategy(
            strategy_id="t1557-003-aws-flow",
            name="VPC Flow Logs DHCP Traffic Monitoring",
            description="Analyse VPC Flow Logs to detect rogue DHCP servers and DHCP spoofing attempts.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, srcaddr, dstaddr, srcport, dstport, protocol, action
| filter dstport = 67 or srcport = 67 or dstport = 68 or srcport = 68
| filter protocol = 17
| stats count() as dhcp_packets by srcaddr, dstaddr, srcport, dstport
| filter dhcp_packets > 100
| sort dhcp_packets desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Monitor DHCP traffic patterns via VPC Flow Logs

Parameters:
  VpcId:
    Type: String
    Description: VPC ID to monitor
  AlertEmail:
    Type: String

Resources:
  # Step 1: CloudWatch Log Group
  FlowLogGroup:
    Type: AWS::Logs::LogGroup
    Properties:
      LogGroupName: /aws/vpc/dhcp-monitoring
      RetentionInDays: 7

  # Step 2: IAM role for Flow Logs
  FlowLogRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: vpc-flow-logs.amazonaws.com
            Action: sts:AssumeRole
      Policies:
        - PolicyName: CloudWatchLogs
          PolicyDocument:
            Statement:
              - Effect: Allow
                Action:
                  - logs:CreateLogGroup
                  - logs:CreateLogStream
                  - logs:PutLogEvents
                Resource: !GetAtt FlowLogGroup.Arn

  # Step 3: VPC Flow Log
  FlowLog:
    Type: AWS::EC2::FlowLog
    Properties:
      ResourceType: VPC
      ResourceIds: [!Ref VpcId]
      TrafficType: ALL
      LogDestinationType: cloud-watch-logs
      LogGroupName: !Ref FlowLogGroup
      DeliverLogsPermissionArn: !GetAtt FlowLogRole.Arn""",
                terraform_template="""# AWS: Monitor DHCP traffic via VPC Flow Logs

variable "vpc_id" {
  type        = string
  description = "VPC ID to monitor"
}

variable "alert_email" {
  type = string
}

# Step 1: CloudWatch Log Group
resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = "/aws/vpc/dhcp-monitoring"
  retention_in_days = 7
}

# Step 2: IAM role for Flow Logs
resource "aws_iam_role" "flow_logs" {
  name = "vpc-dhcp-flow-logs-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "vpc-flow-logs.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "flow_logs" {
  name = "flow-logs-policy"
  role = aws_iam_role.flow_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ]
      Resource = "${aws_cloudwatch_log_group.flow_logs.arn}:*"
    }]
  })
}

# Step 3: VPC Flow Log for DHCP monitoring
resource "aws_flow_log" "dhcp" {
  iam_role_arn    = aws_iam_role.flow_logs.arn
  log_destination = aws_cloudwatch_log_group.flow_logs.arn
  traffic_type    = "ALL"
  vpc_id          = var.vpc_id

  tags = {
    Name    = "DHCP Monitoring"
    Purpose = "Detect rogue DHCP servers"
  }
}""",
                alert_severity="high",
                alert_title="Rogue DHCP Server Detected",
                alert_description_template="Excessive DHCP traffic detected from {srcaddr}. Potential rogue DHCP server or DHCP spoofing attack.",
                investigation_steps=[
                    "Identify the source IP sending DHCP offers/acknowledgements",
                    "Verify if source is an authorised DHCP server",
                    "Review DHCP packet patterns for anomalies",
                    "Check for multiple DHCP servers on same subnet",
                    "Examine instances for unauthorised DHCP server software",
                    "Correlate with DNS query anomalies",
                ],
                containment_actions=[
                    "Isolate suspected rogue DHCP server via security groups",
                    "Block DHCP ports (67/68) from unauthorised sources via NACLs",
                    "Terminate compromised instances if confirmed malicious",
                    "Enable DHCP snooping at network layer if available",
                    "Force static IP configurations for critical systems",
                    "Review and harden EC2 instance launch permissions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal DHCP traffic patterns; whitelist authorised DHCP servers and high-frequency legitimate traffic",
            detection_coverage="30% - detects unexpected DHCP server sources only. Cannot inspect packet contents to verify malicious configuration.",
            evasion_considerations="Low-volume spoofing or spoofing during legitimate DHCP renewal windows may evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-25 (VPC Flow Logs + CloudWatch)",
            prerequisites=["VPC Flow Logs enabled", "CloudWatch Logs"],
        ),
        # Strategy 4: GCP - VPC Network Configuration Monitoring
        DetectionStrategy(
            strategy_id="t1557-003-gcp-network",
            name="GCP VPC Network DHCP Monitoring",
            description="Detect changes to VPC network configurations that affect DHCP behaviour.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.serviceName="compute.googleapis.com"
protoPayload.methodName=~"(v1.compute.networks.patch|v1.compute.networks.insert)"
OR protoPayload.methodName=~"v1.compute.subnetworks.(patch|insert)"''',
                gcp_terraform_template="""# GCP: Monitor VPC network DHCP configuration

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for network changes
resource "google_logging_metric" "network_changes" {
  project = var.project_id
  name   = "vpc-network-dhcp-changes"
  filter = <<-EOT
    protoPayload.serviceName="compute.googleapis.com"
    (protoPayload.methodName=~"v1.compute.networks.(patch|insert)" OR
     protoPayload.methodName=~"v1.compute.subnetworks.(patch|insert)")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "network_change" {
  project      = var.project_id
  display_name = "VPC Network Configuration Modified"
  combiner     = "OR"

  conditions {
    display_name = "Network or subnet configuration changed"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.network_changes.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }

  notification_channels = [google_monitoring_notification_channel.email_s1.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }

  documentation {
    content   = "VPC network or subnet configuration modified. Review for unauthorised DHCP or DNS changes."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="high",
                alert_title="GCP: VPC Network Configuration Modified",
                alert_description_template="VPC network operation {methodName} performed on {resourceName}. Review for DHCP/DNS configuration changes.",
                investigation_steps=[
                    "Verify the principal who performed the network operation",
                    "Review changes to subnet DHCP settings",
                    "Check for modifications to private Google access settings",
                    "Examine DNS server configurations",
                    "Review Cloud Audit Logs for related activities",
                    "Validate firewall rules for DHCP traffic (UDP 67/68)",
                ],
                containment_actions=[
                    "Revert unauthorised network configuration changes",
                    "Revoke compromised service account keys",
                    "Review and restrict compute.networks.* permissions",
                    "Enable organisation policy constraints for network modifications",
                    "Implement VPC Service Controls for sensitive networks",
                    "Enable Private Google Access for controlled DNS resolution",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist legitimate infrastructure changes and terraform/automation service accounts",
            detection_coverage="85% - catches network configuration changes",
            evasion_considerations="Initial network setup may go undetected; compromised admin accounts appear legitimate",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
        # Strategy 5: GCP - VPC Flow Logs DHCP Analysis
        DetectionStrategy(
            strategy_id="t1557-003-gcp-flow",
            name="GCP VPC Flow Logs DHCP Traffic Analysis",
            description="Analyse VPC Flow Logs for rogue DHCP server activity and spoofing attempts.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_subnetwork"
logName="projects/[PROJECT_ID]/logs/compute.googleapis.com%2Fvpc_flows"
(jsonPayload.connection.src_port=67 OR jsonPayload.connection.dest_port=67 OR
 jsonPayload.connection.src_port=68 OR jsonPayload.connection.dest_port=68)
jsonPayload.connection.protocol=17""",
                gcp_terraform_template="""# GCP: Monitor DHCP traffic via VPC Flow Logs

variable "project_id" {
  type = string
}

variable "subnet_name" {
  type = string
}

variable "network_name" {
  type = string
}

variable "region" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Enable VPC Flow Logs on subnet
resource "google_compute_subnetwork" "monitored" {
  name          = var.subnet_name
  ip_cidr_range = "10.0.1.0/24"
  region        = var.region
  network       = var.network_name

  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 1.0
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

# Step 2: Notification channel
resource "google_monitoring_notification_channel" "email_s2" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 3: Log-based metric for DHCP traffic
resource "google_logging_metric" "dhcp_traffic" {
  name   = "dhcp-traffic-detected"
  filter = <<-EOT
    resource.type="gce_subnetwork"
    logName="projects/${var.project_id}/logs/compute.googleapis.com%2Fvpc_flows"
    (jsonPayload.connection.src_port=67 OR jsonPayload.connection.dest_port=67 OR
     jsonPayload.connection.src_port=68 OR jsonPayload.connection.dest_port=68)
    jsonPayload.connection.protocol=17
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "src_ip"
      value_type  = "STRING"
      description = "Source IP"
    }
  }

  label_extractors = {
    "src_ip" = "EXTRACT(jsonPayload.connection.src_ip)"
  }
}

# Alert policy
resource "google_monitoring_alert_policy" "dhcp_anomaly" {
  project      = var.project_id
  display_name = "Rogue DHCP Server Detected"
  combiner     = "OR"

  conditions {
    display_name = "Excessive DHCP traffic from source"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.dhcp_traffic.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 50
      aggregations {
        alignment_period     = "300s"
        per_series_aligner   = "ALIGN_RATE"
        cross_series_reducer = "REDUCE_SUM"
        group_by_fields      = ["metric.label.src_ip"]
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email_s2.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }

  documentation {
    content   = "Excessive DHCP traffic detected from source IP. Potential rogue DHCP server or spoofing attack."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="high",
                alert_title="GCP: Rogue DHCP Server Detected",
                alert_description_template="Excessive DHCP traffic detected from {srcIp}. Potential DHCP spoofing attack.",
                investigation_steps=[
                    "Identify the source IP sending DHCP traffic",
                    "Verify if source is an authorised DHCP server",
                    "Review DHCP traffic patterns and volume",
                    "Check for multiple DHCP servers on same subnet",
                    "Examine instances for unauthorised DHCP software",
                    "Correlate with Cloud DNS query anomalies",
                ],
                containment_actions=[
                    "Apply firewall rules to block DHCP from unauthorised sources",
                    "Delete or stop suspected rogue DHCP instances",
                    "Enable hierarchical firewall policies to prevent DHCP spoofing",
                    "Implement VPC Service Controls for sensitive subnets",
                    "Review and restrict compute instance creation permissions",
                    "Consider static IP assignments for critical systems",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Establish baseline DHCP traffic patterns; whitelist authorised DHCP infrastructure",
            detection_coverage="30% - detects unexpected DHCP server sources only. Cannot inspect packet contents to verify malicious configuration.",
            evasion_considerations="Low-volume spoofing during legitimate renewal windows may evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$15-35 (VPC Flow Logs + monitoring)",
            prerequisites=["VPC Flow Logs enabled on subnets"],
        ),
        # Strategy 6: GCP - Cloud DNS Policy Monitoring
        DetectionStrategy(
            strategy_id="t1557-003-gcp-dns-policy",
            name="GCP Cloud DNS Server Policy Detection",
            description="Detect unauthorised DNS server policies that could redirect DNS traffic.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.serviceName="dns.googleapis.com"
protoPayload.methodName=~"dns.policies.(create|patch|update)"''',
                gcp_terraform_template="""# GCP: Monitor Cloud DNS policy changes

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email_s3" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for DNS policy changes
resource "google_logging_metric" "dns_policy" {
  project = var.project_id
  name   = "dns-policy-changes"
  filter = <<-EOT
    protoPayload.serviceName="dns.googleapis.com"
    protoPayload.methodName=~"dns.policies.(create|patch|update)"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "dns_policy_change" {
  project      = var.project_id
  display_name = "Cloud DNS Policy Modified"
  combiner     = "OR"

  conditions {
    display_name = "DNS policy created or modified"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.dns_policy.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }

  notification_channels = [google_monitoring_notification_channel.email_s3.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }

  documentation {
    content   = "Cloud DNS server policy modified. Review for unauthorised DNS server changes that could redirect traffic."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="high",
                alert_title="GCP: Cloud DNS Policy Modified",
                alert_description_template="DNS policy {methodName} performed. Review for unauthorised DNS server configurations.",
                investigation_steps=[
                    "Verify the principal who modified the DNS policy",
                    "Review DNS server policy inbound/outbound forwarding rules",
                    "Check alternative DNS server IP addresses",
                    "Validate target VPC networks for DNS policy",
                    "Examine Cloud Audit Logs for related DNS changes",
                    "Verify DNSSEC configuration and validation settings",
                ],
                containment_actions=[
                    "Revert unauthorised DNS policy changes immediately",
                    "Revoke compromised service account credentials",
                    "Review and restrict dns.policies.* IAM permissions",
                    "Enable organisation policy constraints for DNS modifications",
                    "Implement Cloud DNS DNSSEC for managed zones",
                    "Audit all DNS policies across organisation",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist legitimate DNS operations and hybrid cloud DNS architectures",
            detection_coverage="90% - catches DNS policy modifications",
            evasion_considerations="Legitimate hybrid DNS may mask malicious configurations",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
        # Azure Strategy: Adversary-in-the-Middle: DHCP Spoofing
        DetectionStrategy(
            strategy_id="t1557003-azure",
            name="Azure Adversary-in-the-Middle: DHCP Spoofing Detection",
            description=(
                "Azure detection for Adversary-in-the-Middle: DHCP Spoofing. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.DEFENDER_ALERT,
            aws_service="n/a",
            azure_service="defender",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                defender_alert_types=[
                    "Detected suspicious network activity",
                    "Suspicious network activity",
                    "Communication with suspicious domain identified by threat intelligence",
                ],
                azure_terraform_template="""# Microsoft Defender for Cloud Detection
# Adversary-in-the-Middle: DHCP Spoofing (T1557.003)
# Microsoft Defender detects Adversary-in-the-Middle: DHCP Spoofing activity

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
  description = "Resource group name"
}

variable "log_analytics_workspace_id" {
  type        = string
  description = "Log Analytics workspace for Defender"
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

# Enable Defender for Cloud plans
resource "azurerm_security_center_subscription_pricing" "defender_servers" {
  tier          = "Standard"
  resource_type = "VirtualMachines"
}

resource "azurerm_security_center_subscription_pricing" "defender_storage" {
  tier          = "Standard"
  resource_type = "StorageAccounts"
}

resource "azurerm_security_center_subscription_pricing" "defender_keyvault" {
  tier          = "Standard"
  resource_type = "KeyVaults"
}

resource "azurerm_security_center_subscription_pricing" "defender_arm" {
  tier          = "Standard"
  resource_type = "Arm"
}

# Action Group for Defender alerts
resource "azurerm_monitor_action_group" "defender_alerts" {
  name                = "defender-t1557-003-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "DefAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Log Analytics query for Defender alerts
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "defender_detection" {
  name                = "defender-t1557-003"
  resource_group_name = var.resource_group_name
  location            = var.location

  evaluation_frequency = "PT5M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 1

  criteria {
    query = <<-QUERY
SecurityAlert
| where TimeGenerated > ago(1h)
| where ProductName == "Azure Security Center" or ProductName == "Microsoft Defender for Cloud"
| where AlertName has_any (

                    "Detected suspicious network activity",
                    "Suspicious network activity",
                    "Communication with suspicious domain identified by threat intelligence"
                )
| project
    TimeGenerated,
    AlertName,
    AlertSeverity,
    Description,
    RemediationSteps,
    ExtendedProperties,
    Entities
    QUERY

    time_aggregation_method = "Count"
    threshold               = 0
    operator                = "GreaterThan"

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  action {
    action_groups = [azurerm_monitor_action_group.defender_alerts.id]
  }

  description = "Microsoft Defender detects Adversary-in-the-Middle: DHCP Spoofing activity"
  display_name = "Defender: Adversary-in-the-Middle: DHCP Spoofing"
  enabled      = true

  tags = {
    "mitre-technique" = "T1557.003"
    "detection-type"  = "security"
  }
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.defender_detection.id
}""",
                alert_severity="high",
                alert_title="Azure: Adversary-in-the-Middle: DHCP Spoofing Detected",
                alert_description_template=(
                    "Adversary-in-the-Middle: DHCP Spoofing activity detected. "
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
        "t1557-003-aws-dhcp",
        "t1557-003-gcp-network",
        "t1557-003-aws-resolver",
        "t1557-003-gcp-dns-policy",
        "t1557-003-aws-flow",
        "t1557-003-gcp-flow",
    ],
    total_effort_hours=4.5,
    coverage_improvement="+12% improvement for Credential Access and Collection tactics",
)
