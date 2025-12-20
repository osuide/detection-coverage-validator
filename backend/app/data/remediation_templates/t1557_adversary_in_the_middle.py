"""
T1557 - Adversary-in-the-Middle

Adversaries position themselves between networked devices to enable follow-on attacks
like network sniffing, data manipulation, and credential theft. Exploits network
protocols (ARP, DNS, LLMNR) to force devices to communicate through attacker-controlled
systems. Used by Sea Turtle, Kimsuky, Mustang Panda.
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
    technique_id="T1557",
    technique_name="Adversary-in-the-Middle",
    tactic_ids=["TA0006", "TA0009"],  # Credential Access, Collection
    mitre_url="https://attack.mitre.org/techniques/T1557/",
    threat_context=ThreatContext(
        description=(
            "Adversaries position themselves between networked devices to enable "
            "network sniffing, data manipulation, and credential theft. By exploiting "
            "network protocols (ARP, DNS, LLMNR), attackers force devices to "
            "communicate through attacker-controlled systems, allowing information "
            "collection and unauthorised actions."
        ),
        attacker_goal="Intercept network traffic to steal credentials and sensitive data",
        why_technique=[
            "Capture credentials transmitted over network",
            "Modify traffic to inject malicious content",
            "Redirect users to attacker-controlled sites",
            "Bypass encryption via TLS downgrade attacks",
            "Intercept API requests and cloud service traffic",
        ],
        known_threat_actors=["Sea Turtle", "Kimsuky", "Mustang Panda"],
        recent_campaigns=[
            Campaign(
                name="ArcaneDoor Campaign",
                year=2024,
                description="Intercepted HTTP traffic on perimeter network devices to monitor and manipulate communications",
                reference_url="https://attack.mitre.org/techniques/T1557/",
            ),
            Campaign(
                name="Sea Turtle DNS Hijacking",
                year=2019,
                description="Modified DNS records at service providers to redirect legitimate traffic through attacker infrastructure",
                reference_url="https://attack.mitre.org/groups/G1041/",
            ),
            Campaign(
                name="Kimsuky PHProxy Deployment",
                year=2022,
                description="Deployed modified PHProxy to examine web traffic between victims and websites",
                reference_url="https://attack.mitre.org/groups/G0094/",
            ),
        ],
        prevalence="moderate",
        trend="stable",
        severity_score=8,
        severity_reasoning=(
            "Enables credential theft and data interception in cloud environments. "
            "Can lead to session hijacking and unauthorised API access. Difficult to "
            "detect when performed at network infrastructure level. Particularly "
            "dangerous for intercepting cloud service communications."
        ),
        business_impact=[
            "Credential theft and account compromise",
            "Data exfiltration and privacy violations",
            "Session hijacking and unauthorised access",
            "Compliance violations from data interception",
            "Reputation damage from security breach",
        ],
        typical_attack_phase="credential_access",
        often_precedes=["T1078.004", "T1528", "T1550"],
        often_follows=["T1190", "T1133"],
    ),
    detection_strategies=[
        # Strategy 1: AWS - VPC DNS Query Logging
        DetectionStrategy(
            strategy_id="t1557-aws-dns",
            name="DNS Anomaly Detection via Route 53 Resolver",
            description="Detect DNS manipulation and suspicious query patterns.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, query_name, query_type, rcode, answers.0.Rdata as resolved_ip
| filter query_type = "A" or query_type = "AAAA"
| filter rcode = "NOERROR"
| stats count(*) as query_count by query_name, resolved_ip, bin(5m)
| filter query_count > 100
| sort query_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect DNS anomalies via Route 53 Resolver Query Logging

Parameters:
  VpcId:
    Type: String
    Description: VPC ID to monitor
  AlertEmail:
    Type: String
    Description: Email for alerts

Resources:
  # Step 1: S3 bucket for DNS logs
  DNSLogBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - ServerSideEncryptionByDefault:
              SSEAlgorithm: AES256

  # Step 2: Route 53 Resolver Query Log Config
  ResolverQueryLogConfig:
    Type: AWS::Route53Resolver::ResolverQueryLogConfig
    Properties:
      Name: VPCDNSQueryLogging
      DestinationArn: !GetAtt DNSLogBucket.Arn

  ResolverQueryLogAssociation:
    Type: AWS::Route53Resolver::ResolverQueryLogConfigAssociation
    Properties:
      ResolverQueryLogConfigId: !Ref ResolverQueryLogConfig
      ResourceId: !Ref VpcId

  # Step 3: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  DNSAnomalyFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Sub '/aws/route53/${ResolverQueryLogConfig}'
      FilterPattern: '[query_type="A*" && rcode="NOERROR"]'
      MetricTransformations:
        - MetricName: DNSQueries
          MetricNamespace: Security/DNS
          MetricValue: "1"

  HighDNSQueryAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: SuspiciousDNSActivity
      MetricName: DNSQueries
      Namespace: Security/DNS
      Statistic: Sum
      Period: 300
      Threshold: 500
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# AWS: Detect DNS anomalies via Route 53 Resolver

variable "vpc_id" {
  type        = string
  description = "VPC ID to monitor"
}

variable "alert_email" {
  type        = string
  description = "Email for alerts"
}

# Step 1: S3 bucket for DNS logs
resource "aws_s3_bucket" "dns_logs" {
  bucket = "dns-query-logs-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "dns_logs" {
  bucket = aws_s3_bucket.dns_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Step 2: Route 53 Resolver Query Logging
resource "aws_route53_resolver_query_log_config" "main" {
  name            = "vpc-dns-query-logging"
  destination_arn = aws_s3_bucket.dns_logs.arn
}

resource "aws_route53_resolver_query_log_config_association" "main" {
  resolver_query_log_config_id = aws_route53_resolver_query_log_config.main.id
  resource_id                  = var.vpc_id
}

# Step 3: CloudWatch alerts
resource "aws_sns_topic" "alerts" {
  name = "dns-anomaly-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "dns_queries" {
  name           = "suspicious-dns-activity"
  log_group_name = "/aws/route53/${aws_route53_resolver_query_log_config.main.id}"
  pattern        = "[query_type=\"A*\" && rcode=\"NOERROR\"]"

  metric_transformation {
    name      = "DNSQueries"
    namespace = "Security/DNS"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "high_dns" {
  alarm_name          = "SuspiciousDNSActivity"
  metric_name         = "DNSQueries"
  namespace           = "Security/DNS"
  statistic           = "Sum"
  period              = 300
  threshold           = 500
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

data "aws_caller_identity" "current" {}""",
                alert_severity="high",
                alert_title="Suspicious DNS Activity Detected",
                alert_description_template="Abnormal DNS query patterns detected in VPC {vpcId}. Potential DNS hijacking or cache poisoning attempt.",
                investigation_steps=[
                    "Review DNS query logs for unusual patterns",
                    "Check resolved IP addresses against known-good baselines",
                    "Verify DNS server configurations are unchanged",
                    "Check for unauthorised changes to Route 53 hosted zones",
                    "Review VPC Flow Logs for connections to suspicious IPs",
                    "Validate TLS certificates for affected domains",
                ],
                containment_actions=[
                    "Enable DNSSEC validation on Route 53 Resolver",
                    "Review and lock down Route 53 IAM permissions",
                    "Implement DNS firewall rules to block malicious domains",
                    "Force DNS resolution through trusted resolvers",
                    "Investigate and block suspicious IP addresses",
                    "Review network ACLs and security group rules",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal DNS patterns; exclude authorised CDN and third-party services",
            detection_coverage="70% - catches DNS-based AitM attacks within VPC",
            evasion_considerations="Direct IP access bypasses DNS monitoring; HTTPS limits visibility",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$15-40 (Route 53 Resolver query logging + CloudWatch)",
            prerequisites=["VPC with workloads", "Route 53 Resolver"],
        ),
        # Strategy 2: AWS - TLS/SSL Certificate Monitoring
        DetectionStrategy(
            strategy_id="t1557-aws-cert",
            name="Unauthorised Certificate Monitoring",
            description="Detect unauthorised SSL/TLS certificates in ACM and CloudFront.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.acm", "aws.cloudfront"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventName": [
                            "ImportCertificate",
                            "RequestCertificate",
                            "UpdateDistribution",
                        ]
                    },
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect unauthorised certificate operations

Parameters:
  AlertEmail:
    Type: String

Resources:
  # Step 1: SNS topic
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: EventBridge rule for certificate operations
  CertificateEventRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.acm, aws.cloudfront]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName:
            - ImportCertificate
            - RequestCertificate
            - UpdateDistribution
      Targets:
        - Id: AlertTopic
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
                terraform_template="""# AWS: Monitor unauthorised certificate operations

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "certificate-operation-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule
resource "aws_cloudwatch_event_rule" "cert_operations" {
  name = "certificate-operations"
  event_pattern = jsonencode({
    source      = ["aws.acm", "aws.cloudfront"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "ImportCertificate",
        "RequestCertificate",
        "UpdateDistribution"
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.cert_operations.name
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
    }]
  })
}""",
                alert_severity="high",
                alert_title="Unauthorised Certificate Operation",
                alert_description_template="Certificate operation {eventName} performed by {userIdentity.principalId} on {certificateArn}.",
                investigation_steps=[
                    "Verify the principal performing the certificate operation",
                    "Check if certificate is for legitimate domain",
                    "Review certificate details and subject alternative names",
                    "Check CloudTrail for related suspicious activities",
                    "Verify no unauthorised CloudFront distributions created",
                    "Review ACM certificate transparency logs",
                ],
                containment_actions=[
                    "Delete unauthorised certificates immediately",
                    "Revoke compromised IAM credentials",
                    "Review and restrict ACM/CloudFront IAM permissions",
                    "Enable SCPs to restrict certificate operations",
                    "Contact affected domain owners if necessary",
                    "Review CloudFront distributions for unauthorised changes",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist authorised DevOps automation and CI/CD pipelines",
            detection_coverage="90% - catches certificate operations via CloudTrail",
            evasion_considerations="Compromised admin credentials may appear legitimate",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled"],
        ),
        # Strategy 3: AWS - VPC Traffic Mirroring Analysis
        DetectionStrategy(
            strategy_id="t1557-aws-mirror",
            name="Network Traffic Analysis via VPC Traffic Mirroring",
            description="Detect ARP spoofing and traffic interception patterns.",
            detection_type=DetectionType.CUSTOM_LAMBDA,
            aws_service="vpc",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                terraform_template="""# AWS: VPC Traffic Mirroring for AitM detection

variable "monitored_eni_id" {
  type        = string
  description = "Network interface to mirror"
}

variable "target_nlb_arn" {
  type        = string
  description = "Network Load Balancer ARN for mirrored traffic"
}

variable "alert_email" {
  type = string
}

# Step 1: Traffic mirror filter
resource "aws_ec2_traffic_mirror_filter" "aitm_detection" {
  description = "Filter for AitM detection"

  # Capture ARP traffic
  ingress_filter_rule {
    rule_number         = 100
    destination_cidr    = "0.0.0.0/0"
    source_cidr         = "0.0.0.0/0"
    protocol            = 0
    traffic_direction   = "ingress"
    rule_action         = "accept"
  }

  egress_filter_rule {
    rule_number         = 100
    destination_cidr    = "0.0.0.0/0"
    source_cidr         = "0.0.0.0/0"
    protocol            = 0
    traffic_direction   = "egress"
    rule_action         = "accept"
  }
}

# Step 2: Traffic mirror target (NLB)
resource "aws_ec2_traffic_mirror_target" "nlb" {
  network_load_balancer_arn = var.target_nlb_arn
}

# Step 3: Traffic mirror session
resource "aws_ec2_traffic_mirror_session" "monitoring" {
  description              = "Monitor for AitM attacks"
  network_interface_id     = var.monitored_eni_id
  traffic_mirror_filter_id = aws_ec2_traffic_mirror_filter.aitm_detection.id
  traffic_mirror_target_id = aws_ec2_traffic_mirror_target.nlb.id
  session_number           = 1
}

# SNS for alerts
resource "aws_sns_topic" "alerts" {
  name = "traffic-anomaly-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}""",
                alert_severity="high",
                alert_title="Network Traffic Anomaly Detected",
                alert_description_template="Suspicious network patterns detected on {networkInterfaceId}. Potential ARP spoofing or traffic interception.",
                investigation_steps=[
                    "Analyse mirrored traffic for ARP anomalies",
                    "Check MAC address tables for duplicates",
                    "Review source/destination IP patterns",
                    "Identify instances with suspicious network behaviour",
                    "Check for gratuitous ARP requests",
                    "Verify network switch configurations",
                ],
                containment_actions=[
                    "Isolate affected instances via security groups",
                    "Implement static ARP entries for critical systems",
                    "Enable VPC Flow Logs for detailed analysis",
                    "Review and harden network ACLs",
                    "Deploy host-based intrusion detection",
                    "Consider network segmentation improvements",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Requires custom analysis logic; baseline normal network patterns",
            detection_coverage="60% - effective for intra-VPC AitM attacks",
            evasion_considerations="Sophisticated attackers may blend with normal traffic patterns",
            implementation_effort=EffortLevel.HIGH,
            implementation_time="4-6 hours",
            estimated_monthly_cost="$30-100 (VPC Traffic Mirroring + NLB + analysis)",
            prerequisites=[
                "VPC Traffic Mirroring support",
                "Network Load Balancer",
                "Analysis infrastructure",
            ],
        ),
        # Strategy 4: GCP - Cloud DNS Logging
        DetectionStrategy(
            strategy_id="t1557-gcp-dns",
            name="GCP Cloud DNS Query Logging",
            description="Detect DNS manipulation via Cloud DNS query logs.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="dns_query"
logName="projects/[PROJECT_ID]/logs/dns.googleapis.com%2Fdns_queries"
jsonPayload.queryType=~"A|AAAA"
jsonPayload.responseCode="NOERROR"''',
                gcp_terraform_template="""# GCP: Detect DNS anomalies via Cloud DNS

variable "project_id" {
  type = string
}

variable "dns_zone_name" {
  type        = string
  description = "DNS zone to monitor"
}

variable "alert_email" {
  type = string
}

# Step 1: Enable DNS query logging on managed zone
resource "google_dns_managed_zone" "monitored_zone" {
  name        = var.dns_zone_name
  dns_name    = "${var.dns_zone_name}.com."
  description = "Monitored DNS zone"

  cloud_logging_config {
    enable_logging = true
  }
}

# Step 2: Notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 3: Log-based metric for suspicious DNS queries
resource "google_logging_metric" "suspicious_dns" {
  name   = "suspicious-dns-queries"
  filter = <<-EOT
    resource.type="dns_query"
    logName="projects/${var.project_id}/logs/dns.googleapis.com%2Fdns_queries"
    jsonPayload.queryType=~"A|AAAA"
    jsonPayload.responseCode="NOERROR"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "query_name"
      value_type  = "STRING"
      description = "DNS query name"
    }
  }

  label_extractors = {
    "query_name" = "EXTRACT(jsonPayload.queryName)"
  }
}

# Alert policy
resource "google_monitoring_alert_policy" "dns_anomaly" {
  display_name = "DNS Anomaly Detected"
  combiner     = "OR"

  conditions {
    display_name = "High DNS query volume"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.suspicious_dns.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 500
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  documentation {
    content   = "Suspicious DNS query patterns detected. Potential DNS hijacking or cache poisoning."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="high",
                alert_title="GCP: Suspicious DNS Activity",
                alert_description_template="Abnormal DNS query patterns detected in Cloud DNS zone {dnsZone}.",
                investigation_steps=[
                    "Review Cloud DNS query logs for unusual patterns",
                    "Check resolved IP addresses against baselines",
                    "Verify Cloud DNS zone configurations",
                    "Check for unauthorised zone modifications",
                    "Review IAM permissions for Cloud DNS",
                    "Validate DNSSEC configuration if enabled",
                ],
                containment_actions=[
                    "Enable DNSSEC on Cloud DNS zones",
                    "Review and restrict Cloud DNS IAM roles",
                    "Implement DNS firewall policies",
                    "Lock down zone record modifications",
                    "Enable Cloud Armor for web applications",
                    "Review VPC firewall rules for DNS traffic",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline legitimate DNS patterns; exclude known CDNs and services",
            detection_coverage="70% - catches DNS-based attacks using Cloud DNS",
            evasion_considerations="Direct IP connections bypass DNS monitoring",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$20-50 (Cloud DNS logging + monitoring)",
            prerequisites=["Cloud DNS managed zones", "Cloud Logging API enabled"],
        ),
        # Strategy 5: GCP - Load Balancer TLS Inspection
        DetectionStrategy(
            strategy_id="t1557-gcp-lb",
            name="GCP Load Balancer Certificate Monitoring",
            description="Detect unauthorised SSL/TLS certificates on load balancers.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.serviceName="compute.googleapis.com"
protoPayload.methodName=~"(insert|update|patch)"
protoPayload.resourceName=~"sslCertificates|targetHttpsProxies"''',
                gcp_terraform_template="""# GCP: Monitor load balancer certificate changes

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for certificate operations
resource "google_logging_metric" "cert_operations" {
  name   = "lb-certificate-operations"
  filter = <<-EOT
    protoPayload.serviceName="compute.googleapis.com"
    protoPayload.methodName=~"(insert|update|patch)"
    protoPayload.resourceName=~"sslCertificates|targetHttpsProxies"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "cert_change" {
  display_name = "Load Balancer Certificate Modified"
  combiner     = "OR"

  conditions {
    display_name = "Certificate operation detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.cert_operations.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  documentation {
    content   = "SSL/TLS certificate modified on load balancer. Review for unauthorised changes."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="high",
                alert_title="GCP: Load Balancer Certificate Modified",
                alert_description_template="SSL/TLS certificate operation {methodName} performed on {resourceName}.",
                investigation_steps=[
                    "Verify the principal performing certificate operation",
                    "Review certificate subject and SANs",
                    "Check Certificate Manager for unauthorised certs",
                    "Validate load balancer configurations",
                    "Review Cloud Audit Logs for related activities",
                    "Check certificate transparency logs",
                ],
                containment_actions=[
                    "Remove unauthorised certificates immediately",
                    "Revoke compromised service account keys",
                    "Review and restrict compute.sslCertificates IAM roles",
                    "Enable organisation policy constraints",
                    "Implement certificate pinning where possible",
                    "Review all load balancer configurations",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist legitimate certificate renewal automation",
            detection_coverage="95% - catches certificate operations via audit logs",
            evasion_considerations="Compromised admin accounts may appear legitimate",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
        # Strategy 6: GCP - VPC Flow Logs Analysis
        DetectionStrategy(
            strategy_id="t1557-gcp-flow",
            name="GCP VPC Flow Logs Anomaly Detection",
            description="Detect network traffic anomalies indicative of AitM attacks.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gce_subnetwork"
logName="projects/[PROJECT_ID]/logs/compute.googleapis.com%2Fvpc_flows"
jsonPayload.connection.protocol=6
jsonPayload.reporter="DEST"''',
                gcp_terraform_template="""# GCP: VPC Flow Logs for network anomaly detection

variable "project_id" {
  type = string
}

variable "subnet_name" {
  type        = string
  description = "Subnet to monitor"
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
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

# Step 2: Notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 3: Log-based metric for suspicious flows
resource "google_logging_metric" "suspicious_flows" {
  name   = "suspicious-network-flows"
  filter = <<-EOT
    resource.type="gce_subnetwork"
    logName="projects/${var.project_id}/logs/compute.googleapis.com%2Fvpc_flows"
    jsonPayload.connection.protocol=6
    jsonPayload.reporter="DEST"
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
resource "google_monitoring_alert_policy" "flow_anomaly" {
  display_name = "VPC Flow Anomaly Detected"
  combiner     = "OR"

  conditions {
    display_name = "High connection rate from single source"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.suspicious_flows.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 1000
      aggregations {
        alignment_period     = "300s"
        per_series_aligner   = "ALIGN_RATE"
        cross_series_reducer = "REDUCE_SUM"
        group_by_fields      = ["metric.label.src_ip"]
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  documentation {
    content   = "Abnormal network flow patterns detected. Potential network interception or scanning."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="medium",
                alert_title="GCP: VPC Network Flow Anomaly",
                alert_description_template="Suspicious network flow patterns detected from {srcIp}.",
                investigation_steps=[
                    "Review VPC Flow Logs for connection patterns",
                    "Identify source and destination instances",
                    "Check for port scanning or connection flooding",
                    "Review firewall rules for misconfigurations",
                    "Verify network topology and routing",
                    "Check instance metadata for compromise",
                ],
                containment_actions=[
                    "Update firewall rules to block malicious IPs",
                    "Isolate affected instances",
                    "Enable Private Google Access to reduce exposure",
                    "Review and harden VPC peering configurations",
                    "Implement Cloud Armor for web workloads",
                    "Consider VPC Service Controls for sensitive data",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Establish baselines for normal traffic patterns; tune thresholds per application",
            detection_coverage="50% - catches network anomalies but requires tuning",
            evasion_considerations="Slow attacks may evade rate-based detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$30-80 (VPC Flow Logs + monitoring)",
            prerequisites=["VPC Flow Logs enabled on subnets"],
        ),
    ],
    recommended_order=[
        "t1557-aws-dns",
        "t1557-gcp-dns",
        "t1557-aws-cert",
        "t1557-gcp-lb",
        "t1557-aws-mirror",
        "t1557-gcp-flow",
    ],
    total_effort_hours=12.0,
    coverage_improvement="+18% improvement for Credential Access and Collection tactics",
)
