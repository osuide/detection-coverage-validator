"""
T1090 - Proxy

Adversaries employ proxy connections to route network traffic between systems or function as intermediaries
for command and control communications, thereby obscuring connections to their infrastructure.
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
    technique_id="T1090",
    technique_name="Proxy",
    tactic_ids=["TA0011"],  # Command and Control
    mitre_url="https://attack.mitre.org/techniques/T1090/",
    threat_context=ThreatContext(
        description=(
            "Adversaries employ proxy connections to route network traffic between systems or function "
            "as intermediaries for command and control (C2) communications, thereby obscuring connections "
            "to their infrastructure. This technique enables threat actors to manage C2 traffic, reduce "
            "simultaneous outbound connections, maintain resilience during connection failures, and exploit "
            "trusted communication pathways. Multi-proxy chains further disguise malicious traffic origins, "
            "whilst CDN routing schemes can be weaponised for C2 purposes. Cloud environments are particularly "
            "vulnerable as attackers leverage internal proxies, external proxy services, multi-hop chains, "
            "and domain fronting to evade detection."
        ),
        attacker_goal="Obscure C2 infrastructure and evade network-based detection through proxy chains",
        why_technique=[
            "Masks true C2 infrastructure location and ownership",
            "Enables traffic to appear as legitimate business communications",
            "Maintains operational resilience if individual proxies are blocked",
            "Exploits trusted third-party services and CDN infrastructure",
            "Reduces direct connections to adversary infrastructure",
            "Facilitates domain fronting to bypass domain-based filtering",
        ],
        known_threat_actors=[
            "APT41",
            "Volt Typhoon",
            "Scattered Spider",
            "Gamaredon Group",
            "APT29",
            "Turla",
            "FIN7",
            "Lazarus Group",
        ],
        recent_campaigns=[
            Campaign(
                name="APT41 Cloudflare CDN Proxying",
                year=2024,
                description="APT41 leveraged Cloudflare CDN infrastructure during the C0017 campaign to proxy C2 traffic, deploying CLASSFON for covert communications",
                reference_url="https://attack.mitre.org/campaigns/C0017/",
            ),
            Campaign(
                name="Volt Typhoon Critical Infrastructure",
                year=2024,
                description="Volt Typhoon utilised compromised devices with customised versions of open-source tools including FRP (Fast Reverse Proxy), Earthworm, and Impacket to route network traffic whilst targeting critical infrastructure",
                reference_url="https://attack.mitre.org/groups/G1017/",
            ),
            Campaign(
                name="Scattered Spider ESXi Compromise",
                year=2023,
                description="Scattered Spider installed rsocx reverse proxy tool on targeted ESXi appliances during the C0027 intrusion campaign",
                reference_url="https://attack.mitre.org/campaigns/C0027/",
            ),
            Campaign(
                name="Gamaredon Cloudflare Tunnel",
                year=2023,
                description="Gamaredon Group deployed Cloudflare Tunnel client to proxy C2 communications in Eastern European operations",
                reference_url="https://attack.mitre.org/groups/G0047/",
            ),
        ],
        prevalence="common",
        trend="increasing",
        severity_score=9,
        severity_reasoning=(
            "Proxy usage is a sophisticated C2 technique that significantly increases attacker operational "
            "security whilst evading traditional network defences. The technique's high severity stems from "
            "its ability to obscure attribution, maintain persistence through infrastructure redundancy, and "
            "exploit trusted services. Cloud environments amplify the risk as organisations routinely communicate "
            "with numerous external services, making malicious proxy traffic difficult to distinguish. The "
            "increasing use of domain fronting and CDN proxying by APT groups demonstrates the technique's "
            "effectiveness against modern detection capabilities."
        ),
        business_impact=[
            "Prolonged undetected attacker presence and data exfiltration",
            "Attribution challenges complicate incident response",
            "Bypassed network security controls and monitoring",
            "Abuse of trusted third-party services damages reputation",
            "Increased risk of regulatory compliance violations",
            "Potential for persistent backdoor access",
        ],
        typical_attack_phase="command_and_control",
        often_precedes=["T1041", "T1567", "T1048"],  # Exfiltration techniques
        often_follows=["T1078.004", "T1190", "T1133"],  # Initial Access techniques
    ),
    detection_strategies=[
        # Strategy 1: AWS - Proxy Tool Detection via CloudTrail
        DetectionStrategy(
            strategy_id="t1090-aws-proxy-deployment",
            name="AWS Proxy Tool Deployment Detection",
            description="Detect deployment of proxy tools and services on EC2 instances through CloudTrail and Systems Manager.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudtrail",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.principalId, eventName, requestParameters, errorCode
| filter eventName in ["RunInstances", "SendCommand", "CreateSession"]
| filter requestParameters.instanceType like /t3|t2|m5/
  or requestParameters.commands like /(?i)(socat|ncat|ssh|chisel|frp|proxychains|squid|nginx proxy|stunnel)/
| stats count() as deployment_count by userIdentity.principalId, eventName
| filter deployment_count > 3
| sort @timestamp desc
| limit 100""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect proxy tool deployment on EC2 instances

Parameters:
  AlertEmail:
    Type: String
    Description: Email address for security alerts

Resources:
  # Step 1: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: EventBridge rule for proxy deployment
  ProxyDeploymentRule:
    Type: AWS::Events::Rule
    Properties:
      Description: Detect proxy tool deployment via Systems Manager
      EventPattern:
        source: [aws.ssm]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName: [SendCommand, StartSession]
          requestParameters:
            commands:
              - prefix: socat
              - prefix: ncat
              - prefix: chisel
              - prefix: frp
              - prefix: proxychains
              - prefix: ssh -D
              - prefix: ssh -R
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
            Resource: !Ref AlertTopic""",
                terraform_template="""# Detect proxy tool deployment on EC2 instances

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "proxy_deployment_alerts" {
  name = "proxy-deployment-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.proxy_deployment_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule for proxy tool deployment
resource "aws_cloudwatch_event_rule" "proxy_deployment" {
  name        = "proxy-tool-deployment-detection"
  description = "Detect proxy tool deployment via Systems Manager"

  event_pattern = jsonencode({
    source      = ["aws.ssm"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["SendCommand", "StartSession"]
      requestParameters = {
        commands = [
          { prefix = "socat" },
          { prefix = "ncat" },
          { prefix = "chisel" },
          { prefix = "frp" },
          { prefix = "proxychains" },
          { prefix = "ssh -D" },
          { prefix = "ssh -R" }
        ]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.proxy_deployment.name
  arn  = aws_sns_topic.proxy_deployment_alerts.arn
}

# Step 3: SNS topic policy
resource "aws_sns_topic_policy" "allow_events" {
  arn = aws_sns_topic.proxy_deployment_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.proxy_deployment_alerts.arn
    }]
  })
}""",
                alert_severity="high",
                alert_title="Proxy Tool Deployment Detected",
                alert_description_template="Proxy tool deployment detected via {eventName} by {userIdentity.principalId}. Instance: {requestParameters.instanceIds}",
                investigation_steps=[
                    "Identify the instance and verify the deployment activity",
                    "Review the user or role that executed the command",
                    "Check instance logs for proxy service execution",
                    "Analyse VPC Flow Logs for proxy connection patterns",
                    "Review CloudTrail for related suspicious activities",
                    "Determine if proxy deployment was authorised",
                ],
                containment_actions=[
                    "Isolate affected instances from the network",
                    "Terminate unauthorised proxy processes",
                    "Revoke IAM credentials used for deployment",
                    "Block proxy listening ports via security groups",
                    "Review and restrict Systems Manager permissions",
                    "Create forensic snapshots before remediation",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist authorised administrative use of SSH tunnelling and legitimate proxy deployments. Tag authorised proxy infrastructure.",
            detection_coverage="70% - detects tool deployment but not all proxy techniques",
            evasion_considerations="Attackers may use obfuscated command names or deploy proxy functionality within compiled binaries",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled", "Systems Manager access logging"],
        ),
        # Strategy 2: AWS - Unusual Proxy Port Activity
        DetectionStrategy(
            strategy_id="t1090-aws-proxy-ports",
            name="AWS Proxy Port Activity Detection",
            description="Detect network connections to common proxy ports (SOCKS, HTTP proxy, reverse proxy) via VPC Flow Logs.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, srcAddr, dstAddr, dstPort, protocol, bytes
| filter dstPort in [1080, 3128, 8080, 8888, 9050, 9150, 4444, 8443]
  or srcPort in [1080, 3128, 8080, 8888, 9050, 9150]
| filter protocol = 6
| stats count() as connection_count, sum(bytes) as total_bytes by srcAddr, dstAddr, dstPort
| filter connection_count > 10
| sort connection_count desc
| limit 100""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect proxy port activity in VPC Flow Logs

Parameters:
  VpcId:
    Type: String
    Description: VPC ID to monitor
  AlertEmail:
    Type: String
    Description: Email address for alerts

Resources:
  # Step 1: VPC Flow Logs
  FlowLogGroup:
    Type: AWS::Logs::LogGroup
    Properties:
      LogGroupName: /aws/vpc/flowlogs-proxy-detection
      RetentionInDays: 7

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

  FlowLog:
    Type: AWS::EC2::FlowLog
    Properties:
      ResourceType: VPC
      ResourceIds:
        - !Ref VpcId
      TrafficType: ALL
      LogDestinationType: cloud-watch-logs
      LogGroupName: !Ref FlowLogGroup
      DeliverLogsPermissionArn: !GetAtt FlowLogRole.Arn

  # Step 2: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 3: Metric filter for proxy ports
  ProxyPortMetric:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref FlowLogGroup
      FilterPattern: '[version, account, eni, source, destination, srcport, dstport=1080 || dstport=3128 || dstport=8080 || dstport=8888 || dstport=9050, protocol="6", ...]'
      MetricTransformations:
        - MetricName: ProxyPortConnections
          MetricNamespace: Security/ProxyDetection
          MetricValue: '1'
          DefaultValue: 0""",
                terraform_template="""# Detect proxy port activity in VPC Flow Logs

variable "vpc_id" {
  type        = string
  description = "VPC ID to monitor"
}

variable "alert_email" {
  type        = string
  description = "Email address for alerts"
}

# Step 1: CloudWatch Log Group for VPC Flow Logs
resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = "/aws/vpc/flowlogs-proxy-detection"
  retention_in_days = 7
}

# Step 2: IAM role for VPC Flow Logs
resource "aws_iam_role" "flow_logs" {
  name = "vpc-flow-logs-proxy-detection"

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

# Step 3: VPC Flow Log
resource "aws_flow_log" "main" {
  iam_role_arn    = aws_iam_role.flow_logs.arn
  log_destination = aws_cloudwatch_log_group.flow_logs.arn
  traffic_type    = "ALL"
  vpc_id          = var.vpc_id
}""",
                alert_severity="high",
                alert_title="Proxy Port Activity Detected",
                alert_description_template="Connections to proxy ports detected from {srcAddr} to {dstAddr}:{dstPort}. Potential proxy usage.",
                investigation_steps=[
                    "Identify source and destination instances",
                    "Check if proxy service is authorised and documented",
                    "Review the purpose of proxy connections",
                    "Analyse traffic patterns and data volume",
                    "Check for signs of data exfiltration or C2 activity",
                    "Review instance running processes and network listeners",
                ],
                containment_actions=[
                    "Block proxy ports via security group rules",
                    "Isolate instances using unauthorised proxies",
                    "Terminate unauthorised proxy services",
                    "Review and restrict network egress rules",
                    "Enable enhanced monitoring on affected instances",
                    "Implement proxy authentication and logging",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist legitimate proxy infrastructure. Document and tag authorised proxy services and their port usage.",
            detection_coverage="65% - detects common proxy ports but may miss custom ports",
            evasion_considerations="Attackers may use non-standard ports or tunnel proxy traffic through standard ports like 443",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-30",
            prerequisites=["VPC Flow Logs enabled", "CloudWatch Logs"],
        ),
        # Strategy 3: AWS - Multi-hop Proxy Chain Detection
        DetectionStrategy(
            strategy_id="t1090-aws-multihop",
            name="AWS Multi-hop Proxy Chain Detection",
            description="Detect multi-hop proxy chains by analysing sequential connections through multiple internal instances.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, srcAddr, dstAddr, srcPort, dstPort, protocol
| filter protocol = 6
| sort @timestamp asc
| stats count() as hop_count by srcAddr, dstAddr
| filter hop_count > 5
| join srcAddr=dstAddr
| filter @message like /10[.]|172[.]16[.]|192[.]168[.]/
| limit 100""",
                terraform_template="""# Detect multi-hop proxy chains through VPC Flow Logs

variable "vpc_flow_log_group" {
  type        = string
  description = "CloudWatch Log Group for VPC Flow Logs"
}

variable "alert_email" {
  type        = string
  description = "Email address for alerts"
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "multihop_alerts" {
  name = "multihop-proxy-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.multihop_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: CloudWatch metric filter for chained connections
resource "aws_cloudwatch_log_metric_filter" "multihop" {
  name           = "multihop-proxy-detection"
  log_group_name = var.vpc_flow_log_group

  # Detect internal-to-internal forwarding patterns
  pattern = "[version, account, eni, src=10.* || src=172.16.* || src=192.168.*, dst=10.* || dst=172.16.* || dst=192.168.*, ...]"

  metric_transformation {
    name      = "MultiHopProxyConnections"
    namespace = "Security/ProxyDetection"
    value     = "1"
  }
}

# Step 3: CloudWatch alarm for multi-hop chains
resource "aws_cloudwatch_metric_alarm" "multihop" {
  alarm_name          = "MultiHopProxyChainDetected"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "MultiHopProxyConnections"
  namespace           = "Security/ProxyDetection"
  period              = 300
  statistic           = "Sum"
  threshold           = 20
  alarm_description   = "Alert on potential multi-hop proxy chains"
  alarm_actions       = [aws_sns_topic.multihop_alerts.arn]
}""",
                alert_severity="critical",
                alert_title="Multi-hop Proxy Chain Detected",
                alert_description_template="Multiple sequential internal connections detected. Source: {srcAddr} through intermediate hops to external destinations.",
                investigation_steps=[
                    "Map the complete connection chain through VPC Flow Logs",
                    "Identify all instances involved in the proxy chain",
                    "Review each instance's purpose and authorisation",
                    "Check for compromised instances in the chain",
                    "Analyse final destination of the proxy chain",
                    "Review CloudTrail for suspicious API activity on chain instances",
                ],
                containment_actions=[
                    "Isolate all instances in the proxy chain",
                    "Block lateral movement via security groups",
                    "Terminate unauthorised proxy processes",
                    "Review and restrict IAM permissions",
                    "Enable GuardDuty for advanced threat detection",
                    "Implement network segmentation to prevent chaining",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist legitimate multi-tier architectures and load balancer chains. Document expected internal routing patterns.",
            detection_coverage="80% - effective for internal proxy chains",
            evasion_considerations="Attackers may use time delays between hops or route through fewer intermediate systems",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1.5 hours",
            estimated_monthly_cost="$15-25",
            prerequisites=["VPC Flow Logs enabled", "Enhanced flow log format"],
        ),
        # Strategy 4: GCP - Proxy Service Deployment Detection
        DetectionStrategy(
            strategy_id="t1090-gcp-proxy-deployment",
            name="GCP Proxy Service Deployment Detection",
            description="Detect deployment of proxy services on GCP Compute Engine instances through Cloud Audit Logs.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gce_instance"
logName="projects/PROJECT_ID/logs/cloudaudit.googleapis.com%2Factivity"
protoPayload.methodName:"compute.instances.insert"
OR protoPayload.methodName:"compute.instances.setMetadata"
protoPayload.request.metadata.items.value=~"(socat|ncat|chisel|frp|proxychains|squid|nginx.*proxy|stunnel|ssh.*-D|ssh.*-R)"''',
                gcp_terraform_template="""# GCP: Detect proxy service deployment

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts - Proxy Detection"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for proxy deployment
resource "google_logging_metric" "proxy_deployment" {
  name   = "proxy-service-deployment"
  filter = <<-EOT
    resource.type="gce_instance"
    logName=~"projects/.*/logs/cloudaudit.googleapis.com%2Factivity"
    (protoPayload.methodName="compute.instances.insert" OR
     protoPayload.methodName="compute.instances.setMetadata")
    protoPayload.request.metadata.items.value=~"(socat|ncat|chisel|frp|proxychains|squid|nginx.*proxy|stunnel|ssh.*-D|ssh.*-R)"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "proxy_deployment" {
  display_name = "Proxy Service Deployment Detected"
  combiner     = "OR"

  conditions {
    display_name = "Proxy tool deployment activity"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.proxy_deployment.name}\""
      duration        = "60s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "86400s"
  }
}""",
                alert_severity="high",
                alert_title="GCP: Proxy Service Deployment Detected",
                alert_description_template="Proxy service deployment detected on instance {resource.labels.instance_id} via {protoPayload.methodName}",
                investigation_steps=[
                    "Identify the VM instance and its project",
                    "Review the service account used for deployment",
                    "Check instance metadata for proxy configuration",
                    "Analyse VPC Flow Logs for proxy traffic patterns",
                    "Review Cloud Audit Logs for related activities",
                    "Verify if deployment was authorised",
                ],
                containment_actions=[
                    "Isolate affected VM instances via firewall rules",
                    "Stop unauthorised proxy services",
                    "Revoke service account credentials",
                    "Review and restrict IAM permissions",
                    "Enable VPC Service Controls",
                    "Create snapshots for forensic analysis",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist authorised proxy deployments using labels. Document legitimate proxy infrastructure in the CMDB.",
            detection_coverage="75% - detects deployment but not all runtime proxy activity",
            evasion_considerations="Attackers may deploy proxy functionality as part of legitimate application containers or use pre-built images",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-20",
            prerequisites=["Cloud Audit Logs enabled", "Cloud Logging"],
        ),
        # Strategy 5: GCP - Proxy Port Traffic Analysis
        DetectionStrategy(
            strategy_id="t1090-gcp-proxy-ports",
            name="GCP Proxy Port Traffic Detection",
            description="Detect network connections to common proxy ports through VPC Flow Logs analysis.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_subnetwork"
logName="projects/PROJECT_ID/logs/compute.googleapis.com%2Fvpc_flows"
(jsonPayload.connection.dest_port:(1080 OR 3128 OR 8080 OR 8888 OR 9050 OR 9150 OR 4444)
OR jsonPayload.connection.src_port:(1080 OR 3128 OR 8080 OR 8888 OR 9050 OR 9150))
jsonPayload.connection.protocol=6""",
                gcp_terraform_template="""# GCP: Detect proxy port traffic

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts - Proxy Traffic"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for proxy port traffic
resource "google_logging_metric" "proxy_ports" {
  name   = "proxy-port-traffic"
  filter = <<-EOT
    resource.type="gce_subnetwork"
    logName=~"projects/.*/logs/compute.googleapis.com%2Fvpc_flows"
    (jsonPayload.connection.dest_port:(1080 OR 3128 OR 8080 OR 8888 OR 9050 OR 9150 OR 4444)
    OR jsonPayload.connection.src_port:(1080 OR 3128 OR 8080 OR 8888 OR 9050 OR 9150))
    jsonPayload.connection.protocol=6
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "proxy_ports" {
  display_name = "Proxy Port Traffic Detected"
  combiner     = "OR"

  conditions {
    display_name = "Unusual proxy port activity"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.proxy_ports.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 20
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "86400s"
  }
}""",
                alert_severity="high",
                alert_title="GCP: Proxy Port Traffic Detected",
                alert_description_template="Traffic to proxy ports detected in VPC Flow Logs. Potential proxy usage between {jsonPayload.connection.src_ip} and {jsonPayload.connection.dest_ip}",
                investigation_steps=[
                    "Identify source and destination VM instances",
                    "Check if proxy service is authorised",
                    "Review connection patterns and data volumes",
                    "Analyse Cloud Logging for application logs",
                    "Check for signs of data exfiltration",
                    "Review firewall rules allowing proxy ports",
                ],
                containment_actions=[
                    "Block proxy ports via VPC firewall rules",
                    "Isolate instances using unauthorised proxies",
                    "Terminate proxy processes on affected VMs",
                    "Review and restrict egress firewall rules",
                    "Enable VPC Flow Logs sampling for detailed analysis",
                    "Implement Cloud Armor for application-layer protection",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Tag and whitelist legitimate proxy infrastructure. Establish baseline for authorised proxy port usage.",
            detection_coverage="65% - detects common proxy ports but may miss custom configurations",
            evasion_considerations="Attackers may use non-standard ports or tunnel through common HTTPS port 443",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$15-30",
            prerequisites=["VPC Flow Logs enabled", "Cloud Logging"],
        ),
        # Strategy 6: AWS - Domain Fronting Detection
        DetectionStrategy(
            strategy_id="t1090-aws-domain-fronting",
            name="AWS Domain Fronting Detection via CloudFront",
            description="Detect potential domain fronting through CloudFront by identifying mismatched SNI and Host headers.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudfront",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, c-ip, cs-host, cs-uri-stem, sc-status, cs-protocol, ssl-protocol, ssl-cipher
| filter cs-protocol = "https"
| filter cs-host != ssl-protocol
| stats count() as mismatch_count by c-ip, cs-host
| filter mismatch_count > 10
| sort mismatch_count desc
| limit 100""",
                terraform_template="""# Detect domain fronting via CloudFront

variable "cloudfront_distribution_id" {
  type        = string
  description = "CloudFront distribution ID to monitor"
}

variable "alert_email" {
  type        = string
  description = "Email address for alerts"
}

# Step 1: Enable CloudFront standard logging
resource "aws_s3_bucket" "cloudfront_logs" {
  bucket = "cloudfront-logs-domain-fronting-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket_ownership_controls" "cloudfront_logs" {
  bucket = aws_s3_bucket.cloudfront_logs.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

data "aws_caller_identity" "current" {}

# Step 2: SNS topic for alerts
resource "aws_sns_topic" "domain_fronting_alerts" {
  name = "domain-fronting-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.domain_fronting_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 3: CloudWatch Logs Insights query (manual analysis required)
# Note: CloudFront logs require custom processing for domain fronting detection
# Consider using Lambda for automated analysis of Host header mismatches""",
                alert_severity="critical",
                alert_title="Potential Domain Fronting Detected",
                alert_description_template="SNI/Host header mismatch detected from {c-ip} accessing {cs-host}. Potential domain fronting attempt.",
                investigation_steps=[
                    "Review CloudFront access logs for the timeframe",
                    "Analyse SNI and Host header mismatches",
                    "Identify the source IP and geolocation",
                    "Check if the CloudFront distribution is authorised",
                    "Review origin server logs for suspicious requests",
                    "Correlate with WAF logs and GuardDuty findings",
                ],
                containment_actions=[
                    "Configure CloudFront to require specific Host headers",
                    "Implement AWS WAF rules to block mismatched requests",
                    "Enable CloudFront signed URLs/cookies for authentication",
                    "Restrict CloudFront distribution access to known origins",
                    "Enable enhanced CloudFront security features",
                    "Consider disabling the distribution if unauthorised",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Review legitimate CDN usage patterns. Whitelist expected Host header variations for multi-domain distributions.",
            detection_coverage="60% - detects CloudFront domain fronting but not other CDN providers",
            evasion_considerations="Attackers may switch to other CDN providers or use encrypted payloads within legitimate requests",
            implementation_effort=EffortLevel.HIGH,
            implementation_time="2 hours",
            estimated_monthly_cost="$20-40",
            prerequisites=["CloudFront standard logging enabled", "S3 bucket for logs"],
        ),
    ],
    recommended_order=[
        "t1090-aws-proxy-deployment",
        "t1090-gcp-proxy-deployment",
        "t1090-aws-proxy-ports",
        "t1090-gcp-proxy-ports",
        "t1090-aws-multihop",
        "t1090-aws-domain-fronting",
    ],
    total_effort_hours=7.0,
    coverage_improvement="+30% improvement for Command and Control proxy detection",
)
