"""
T1572 - Protocol Tunneling

Adversaries encapsulate one network protocol within another to conceal malicious traffic.
Used by Sandworm Team, Scattered Spider, FIN7, Cobalt Group, Salt Typhoon, Magic Hound.
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
    technique_id="T1572",
    technique_name="Protocol Tunneling",
    tactic_ids=["TA0011"],  # Command and Control
    mitre_url="https://attack.mitre.org/techniques/T1572/",
    threat_context=ThreatContext(
        description=(
            "Adversaries encapsulate one network protocol within another to conceal malicious "
            "traffic and bypass security controls. This technique allows attackers to hide command-and-control "
            "communications by blending them with legitimate traffic or adding encryption layers similar to VPN "
            "technology. Common methods include SSH/PLINK tunnelling, DNS over HTTPS, HTTP/HTTPS encapsulation, "
            "RDP tunnelling, SOCKS proxies, and Generic Routing Encapsulation (GRE). Protocol tunnelling enables "
            "routing of traffic that would normally be filtered by network appliances."
        ),
        attacker_goal="Conceal command-and-control traffic and bypass network security controls using protocol encapsulation",
        why_technique=[
            "Blends malicious traffic with legitimate protocols",
            "Bypasses traditional network filtering and inspection",
            "Adds encryption to hide payload content",
            "Enables access to normally blocked services",
            "Difficult to detect without deep packet inspection",
            "Common tools (SSH, ngrok, chisel) readily available",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "Protocol tunnelling is highly effective at bypassing network security controls and is "
            "widely adopted by both sophisticated APT groups and commodity malware. The technique "
            "enables persistent command-and-control channels that blend with legitimate traffic, making "
            "detection challenging without specialised monitoring. High severity due to widespread tooling "
            "availability, difficulty of detection, and effectiveness at maintaining covert communications."
        ),
        business_impact=[
            "Persistent unauthorised access to cloud infrastructure",
            "Bypassed network security controls and monitoring",
            "Data exfiltration via concealed channels",
            "Lateral movement enablement through tunnelled protocols",
            "Compliance violations from undetected C2 traffic",
            "Increased dwell time and incident response costs",
        ],
        typical_attack_phase="command_and_control",
        often_precedes=["T1041", "T1048", "T1071"],
        often_follows=["T1078.004", "T1190", "T1133"],
    ),
    detection_strategies=[
        # Strategy 1: AWS - SSH Tunnelling Detection
        DetectionStrategy(
            strategy_id="t1572-aws-ssh-tunnel",
            name="AWS SSH Tunnelling Detection",
            description="Detect SSH connections with port forwarding or tunnelling behaviour via CloudTrail and VPC Flow Logs.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, sourceIPAddress, userIdentity.principalId, requestParameters
| filter eventName = "RunInstances" or eventName = "AuthorizeSecurityGroupIngress"
| filter requestParameters.ipPermissions.items.0.toPort = 22
  or requestParameters.ipPermissions.items.0.fromPort = 22
| sort @timestamp desc
| limit 100""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect SSH tunnelling and port forwarding activity

Parameters:
  AlertEmail:
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

  # Step 2: EventBridge rule for SSH security group changes
  SSHTunnelRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.ec2]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName:
            - AuthorizeSecurityGroupIngress
            - AuthorizeSecurityGroupEgress
          requestParameters:
            ipPermissions:
              items:
                toPort: [22]
      Targets:
        - Id: Alert
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
                aws:SourceArn: !GetAtt SSHTunnelRule.Arn""",
                terraform_template="""# Detect AWS SSH tunnelling activity

variable "alert_email" {
  type = string
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "ssh-tunnel-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule for SSH security group changes
resource "aws_cloudwatch_event_rule" "ssh_tunnel" {
  name = "ssh-tunnelling-detection"
  event_pattern = jsonencode({
    source      = ["aws.ec2"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "AuthorizeSecurityGroupIngress",
        "AuthorizeSecurityGroupEgress"
      ]
      requestParameters = {
        ipPermissions = {
          items = {
            toPort = [22]
          }
        }
      }
    }
  })
}

resource "aws_sqs_queue" "dlq" {
  name                      = "protocol-tunneling-dlq"
  message_retention_seconds = 1209600
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.ssh_tunnel.name
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

resource "aws_sqs_queue_policy" "dlq_policy" {
  queue_url = aws_sqs_queue.dlq.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.dlq.arn
      Condition = {
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.ssh_tunnel.arn
        }
      }
    }]
  })
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
              aws_cloudwatch_event_rule.ssh_tunnel.arn,
              aws_cloudwatch_event_rule.ssm_port_forward.arn,
            ]
          }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="SSH Tunnelling Configuration Detected",
                alert_description_template="SSH security group rule modified for {groupId}. This may indicate protocol tunnelling setup.",
                investigation_steps=[
                    "Identify who modified the security group",
                    "Review the CIDR ranges authorised for SSH access",
                    "Check if this is an authorised administrative change",
                    "Examine recent SSH connection patterns in VPC Flow Logs",
                    "Review CloudWatch logs for SSH session establishment",
                    "Check for tools like plink, ssh, or ngrok on instances",
                ],
                containment_actions=[
                    "Remove unauthorised SSH security group rules",
                    "Restrict SSH access to bastion hosts only",
                    "Enable MFA for SSH connections",
                    "Review and restrict ec2:AuthorizeSecurityGroup* permissions",
                    "Enable Session Manager as alternative to SSH",
                    "Implement network segmentation to limit tunnelling impact",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist authorised infrastructure teams; exclude bastion host security groups",
            detection_coverage="70% - catches SSH configuration changes",
            evasion_considerations="Attacker may use existing SSH configurations or non-standard ports",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled"],
        ),
        # Strategy 2: AWS - Unusual Encrypted Traffic Patterns
        DetectionStrategy(
            strategy_id="t1572-aws-encrypted-anomaly",
            name="Unusual Encrypted Traffic Detection",
            description="Detect encrypted traffic on non-standard ports that may indicate protocol tunnelling.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, srcAddr, dstAddr, dstPort, protocol, bytes
| filter dstPort not in [443, 22, 3389, 993, 995, 465, 587]
| filter bytes > 1000000
| stats sum(bytes) as total_bytes, count(*) as connections by srcAddr, dstPort, bin(5m)
| filter connections > 50 or total_bytes > 10485760
| sort total_bytes desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect unusual encrypted traffic patterns indicating tunnelling

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

  # Step 2: Metric filter for non-standard port traffic
  TunnelTrafficFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref VPCFlowLogGroup
      FilterPattern: '[version, account, eni, source, destination, srcport, dstport != 443 && dstport != 22 && dstport != 3389, protocol, packets, bytes > 1000000, ...]'
      MetricTransformations:
        - MetricName: NonStandardEncryptedTraffic
          MetricNamespace: Security
          MetricValue: "$bytes"
          Unit: Bytes

  # Step 3: CloudWatch alarm
  TunnelAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: Protocol-Tunnelling-Detected
      MetricName: NonStandardEncryptedTraffic
      Namespace: Security
      Statistic: Sum
      Period: 300
      Threshold: 10485760
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect unusual encrypted traffic patterns

variable "alert_email" { type = string }
variable "vpc_flow_log_group" { type = string }

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "tunnel-traffic-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for non-standard port traffic
resource "aws_cloudwatch_log_metric_filter" "tunnel_traffic" {
  name           = "non-standard-encrypted-traffic"
  log_group_name = var.vpc_flow_log_group
  pattern        = "[version, account, eni, source, destination, srcport, dstport != 443 && dstport != 22 && dstport != 3389, protocol, packets, bytes > 1000000, ...]"

  metric_transformation {
    name      = "NonStandardEncryptedTraffic"
    namespace = "Security"
    value     = "$bytes"
    unit      = "Bytes"
  }
}

# Step 3: CloudWatch alarm
resource "aws_cloudwatch_metric_alarm" "tunnel_alarm" {
  alarm_name          = "Protocol-Tunnelling-Detected"
  metric_name         = "NonStandardEncryptedTraffic"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 10485760
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="high",
                alert_title="Unusual Encrypted Traffic Pattern Detected",
                alert_description_template="High-volume traffic on non-standard port {dstPort} from {srcAddr}: {total_bytes} bytes in {connections} connections.",
                investigation_steps=[
                    "Identify source and destination instances",
                    "Analyse traffic patterns and connection duration",
                    "Check for tunnelling tools (ngrok, chisel, plink, socat)",
                    "Review processes establishing network connections",
                    "Examine user activity and authentication logs",
                    "Correlate with other security events",
                ],
                containment_actions=[
                    "Block traffic to suspicious destination ports",
                    "Isolate affected instances from network",
                    "Terminate suspicious processes",
                    "Review and restrict egress firewall rules",
                    "Enable enhanced monitoring on affected resources",
                    "Conduct forensic analysis of instance",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known application ports; establish baseline traffic patterns",
            detection_coverage="75% - catches unusual encrypted traffic",
            evasion_considerations="Using standard ports (443, 22); low-volume tunnelling",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-20",
            prerequisites=["VPC Flow Logs enabled", "CloudWatch Logs"],
        ),
        # Strategy 3: AWS - Systems Manager Session Tunnelling
        DetectionStrategy(
            strategy_id="t1572-aws-ssm-tunnel",
            name="AWS Systems Manager Port Forwarding Detection",
            description="Detect port forwarding via AWS Systems Manager Session Manager which can be abused for tunnelling.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.ssm"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventName": ["StartSession"],
                        "requestParameters": {
                            "documentName": ["AWS-StartPortForwardingSession"]
                        },
                    },
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect Systems Manager port forwarding sessions

Parameters:
  AlertEmail:
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

  # Step 2: EventBridge rule for SSM port forwarding
  SSMPortForwardRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.ssm]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName: [StartSession]
          requestParameters:
            documentName: [AWS-StartPortForwardingSession]
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
                aws:SourceArn: !GetAtt SSMPortForwardRule.Arn""",
                terraform_template="""# Detect Systems Manager port forwarding

variable "alert_email" {
  type = string
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "ssm-port-forward-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule for SSM port forwarding
resource "aws_cloudwatch_event_rule" "ssm_port_forward" {
  name = "ssm-port-forwarding-detection"
  event_pattern = jsonencode({
    source      = ["aws.ssm"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["StartSession"]
      requestParameters = {
        documentName = ["AWS-StartPortForwardingSession"]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.ssm_port_forward.name
target_id = "SendToSNS"
  arn  = aws_sns_topic.alerts.arn
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
              aws_cloudwatch_event_rule.ssh_tunnel.arn,
              aws_cloudwatch_event_rule.ssm_port_forward.arn,
            ]
          }
      }
    }]
  })
}""",
                alert_severity="medium",
                alert_title="Systems Manager Port Forwarding Session Started",
                alert_description_template="Port forwarding session initiated via Systems Manager by {userIdentity.principalId} to {target}.",
                investigation_steps=[
                    "Identify the user who started the session",
                    "Review the target instance and ports being forwarded",
                    "Check if this is authorised administrative activity",
                    "Examine session duration and data transferred",
                    "Review recent authentication events for the principal",
                    "Check for other suspicious Sessions Manager activity",
                ],
                containment_actions=[
                    "Terminate unauthorised SSM sessions",
                    "Review and restrict ssm:StartSession permissions",
                    "Implement session logging and monitoring",
                    "Require MFA for sensitive SSM operations",
                    "Apply IAM conditions to restrict port forwarding document usage",
                    "Enable Session Manager logging to S3/CloudWatch",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist authorised DevOps and infrastructure teams",
            detection_coverage="95% - catches all SSM port forwarding sessions",
            evasion_considerations="Using alternative tunnelling methods; SSH directly to instances",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled", "Systems Manager enabled"],
        ),
        # Strategy 4: GCP - SSH Tunnelling Detection
        DetectionStrategy(
            strategy_id="t1572-gcp-ssh-tunnel",
            name="GCP SSH Tunnelling Detection",
            description="Detect SSH tunnelling activity via Cloud Audit Logs and VPC Flow Logs.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName="v1.compute.firewalls.insert"
OR protoPayload.methodName="v1.compute.firewalls.patch"
protoPayload.serviceName="compute.googleapis.com"
protoPayload.request.allowed.ports="22"''',
                gcp_terraform_template="""# GCP: Detect SSH tunnelling configuration

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

# Step 2: Log-based metric for SSH firewall changes
resource "google_logging_metric" "ssh_tunnel" {
  project = var.project_id
  name   = "ssh-tunnel-config"
  filter = <<-EOT
    protoPayload.serviceName="compute.googleapis.com"
    (protoPayload.methodName="v1.compute.firewalls.insert" OR
     protoPayload.methodName="v1.compute.firewalls.patch")
    protoPayload.request.allowed.ports="22"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "ssh_tunnel" {
  project      = var.project_id
  display_name = "SSH Tunnelling Configuration Detected"
  combiner     = "OR"

  conditions {
    display_name = "SSH firewall rule created or modified"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.ssh_tunnel.name}\""
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
}""",
                alert_severity="high",
                alert_title="GCP: SSH Tunnelling Configuration Detected",
                alert_description_template="SSH firewall rule created or modified. This may indicate protocol tunnelling setup.",
                investigation_steps=[
                    "Identify who created or modified the firewall rule",
                    "Review the source IP ranges authorised for SSH",
                    "Check if this is an authorised infrastructure change",
                    "Examine VPC Flow Logs for SSH connection patterns",
                    "Review Cloud Logging for SSH session activity",
                    "Check instances for tunnelling tools (plink, chisel, ngrok)",
                ],
                containment_actions=[
                    "Remove unauthorised SSH firewall rules",
                    "Restrict SSH access to Identity-Aware Proxy only",
                    "Enable OS Login for managed SSH access",
                    "Review and restrict compute.firewalls.* permissions",
                    "Implement VPC Service Controls",
                    "Enable Private Google Access to reduce internet exposure",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist authorised infrastructure and DevOps teams",
            detection_coverage="70% - catches SSH firewall configuration",
            evasion_considerations="Using existing firewall rules; non-standard ports",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
        # Strategy 5: GCP - Unusual Encrypted Traffic Patterns
        DetectionStrategy(
            strategy_id="t1572-gcp-encrypted-anomaly",
            name="GCP Unusual Encrypted Traffic Detection",
            description="Detect encrypted traffic on non-standard ports via VPC Flow Logs.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_subnetwork"
logName="projects/PROJECT_ID/logs/compute.googleapis.com%2Fvpc_flows"
jsonPayload.connection.dest_port!=(443 OR 22 OR 3389 OR 993 OR 995)
jsonPayload.bytes_sent>1048576""",
                gcp_terraform_template="""# GCP: Detect unusual encrypted traffic patterns

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email_s2" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for non-standard port traffic
resource "google_logging_metric" "tunnel_traffic" {
  project = var.project_id
  name   = "non-standard-encrypted-traffic"
  filter = <<-EOT
    resource.type="gce_subnetwork"
    logName=~"projects/.*/logs/compute.googleapis.com%2Fvpc_flows"
    jsonPayload.connection.dest_port!=443
    jsonPayload.connection.dest_port!=22
    jsonPayload.connection.dest_port!=3389
    jsonPayload.bytes_sent>1048576
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "tunnel_traffic" {
  project      = var.project_id
  display_name = "Unusual Encrypted Traffic Detected"
  combiner     = "OR"

  conditions {
    display_name = "High-volume traffic on non-standard ports"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.tunnel_traffic.name}\""
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
                alert_title="GCP: Unusual Encrypted Traffic Pattern Detected",
                alert_description_template="High-volume traffic detected on non-standard ports. May indicate protocol tunnelling.",
                investigation_steps=[
                    "Identify source and destination instances",
                    "Analyse traffic volume and connection patterns",
                    "Check for tunnelling tools on source instances",
                    "Review processes establishing network connections",
                    "Examine user authentication and activity logs",
                    "Correlate with other security events and alerts",
                ],
                containment_actions=[
                    "Block traffic to suspicious ports via firewall",
                    "Isolate affected instances",
                    "Terminate suspicious processes",
                    "Review and restrict egress firewall rules",
                    "Enable enhanced monitoring and logging",
                    "Conduct forensic analysis if compromise confirmed",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known application ports; establish traffic baselines",
            detection_coverage="75% - catches unusual encrypted traffic",
            evasion_considerations="Using standard ports; low-volume tunnelling",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-20",
            prerequisites=["VPC Flow Logs enabled on subnets", "Cloud Logging"],
        ),
        # Strategy 6: GCP - Cloud VPN Tunnel Monitoring
        DetectionStrategy(
            strategy_id="t1572-gcp-vpn-tunnel",
            name="GCP Cloud VPN Tunnel Monitoring",
            description="Monitor Cloud VPN tunnel creation which could be abused for protocol tunnelling.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName="v1.compute.vpnTunnels.insert"
OR protoPayload.methodName="v1.compute.vpnGateways.insert"
protoPayload.serviceName="compute.googleapis.com"''',
                gcp_terraform_template="""# GCP: Monitor Cloud VPN tunnel creation

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

# Step 2: Log-based metric for VPN tunnel creation
resource "google_logging_metric" "vpn_tunnel" {
  project = var.project_id
  name   = "vpn-tunnel-creation"
  filter = <<-EOT
    protoPayload.serviceName="compute.googleapis.com"
    (protoPayload.methodName="v1.compute.vpnTunnels.insert" OR
     protoPayload.methodName="v1.compute.vpnGateways.insert")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "vpn_tunnel" {
  project      = var.project_id
  display_name = "Cloud VPN Tunnel Created"
  combiner     = "OR"

  conditions {
    display_name = "VPN tunnel or gateway created"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.vpn_tunnel.name}\""
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
}""",
                alert_severity="medium",
                alert_title="GCP: Cloud VPN Tunnel Created",
                alert_description_template="VPN tunnel or gateway created. Verify this is authorised infrastructure.",
                investigation_steps=[
                    "Identify who created the VPN tunnel or gateway",
                    "Review VPN configuration and peer IP addresses",
                    "Check if this is part of authorised network changes",
                    "Examine traffic patterns through the VPN tunnel",
                    "Review organisation's VPN deployment policies",
                    "Verify business justification for VPN creation",
                ],
                containment_actions=[
                    "Delete unauthorised VPN tunnels or gateways",
                    "Review and restrict compute.vpn* permissions",
                    "Implement organisation policy constraints for VPN",
                    "Enable VPC Flow Logs on VPN-connected networks",
                    "Require approval workflow for VPN infrastructure",
                    "Audit all existing VPN configurations",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist authorised network engineering teams and change management systems",
            detection_coverage="95% - catches all VPN tunnel creation",
            evasion_considerations="Using existing VPN infrastructure; application-layer tunnelling",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
    ],
    recommended_order=[
        "t1572-aws-ssh-tunnel",
        "t1572-gcp-ssh-tunnel",
        "t1572-aws-ssm-tunnel",
        "t1572-aws-encrypted-anomaly",
        "t1572-gcp-encrypted-anomaly",
        "t1572-gcp-vpn-tunnel",
    ],
    total_effort_hours=4.5,
    coverage_improvement="+18% improvement for Command and Control tactic",
)
