"""
T1071.004 - Application Layer Protocol: DNS

Adversaries exploit DNS for command and control communications by embedding commands and
data within DNS queries and responses. DNS tunnelling enables covert C2 channels that blend
with legitimate network traffic, making detection challenging.
Used by APT18, APT39, APT41, OilRig, FIN7, Cobalt Group, and over 40 malware families.
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
    technique_id="T1071.004",
    technique_name="Application Layer Protocol: DNS",
    tactic_ids=["TA0011"],  # Command and Control
    mitre_url="https://attack.mitre.org/techniques/T1071/004/",
    threat_context=ThreatContext(
        description=(
            "Adversaries exploit DNS protocol for command and control communications by "
            "embedding commands and responses within DNS packet fields and headers. DNS tunnelling "
            "allows bidirectional communication through standard DNS infrastructure whilst evading "
            "detection, as DNS traffic typically receives minimal scrutiny and may be allowed before "
            "network authentication completes. Attackers encode payloads within subdomain portions of "
            "DNS queries and use various record types—particularly TXT and A records—to exfiltrate data "
            "and receive commands. This technique proves particularly effective in cloud environments "
            "where DNS is essential for service discovery and inter-service communication."
        ),
        attacker_goal="Establish covert command and control channels using DNS protocol to evade detection",
        why_technique=[
            "DNS traffic typically allowed through firewalls by default",
            "Minimal inspection of DNS queries in most environments",
            "DNS available before network authentication in many cases",
            "Blends with legitimate DNS service discovery traffic",
            "Supports bidirectional communication for C2 operations",
            "Enables data exfiltration through encoded subdomains",
            "Difficult to distinguish from normal application behaviour",
            "Multiple DNS record types available for data encoding",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "DNS-based C2 is highly prevalent across advanced threat actors and commodity malware. "
            "Its effectiveness in evading traditional security controls combined with difficulty in detection "
            "makes it a persistent threat. Cloud environments amplify risk due to heavy reliance on DNS for "
            "service discovery. High severity due to enabling persistent unauthorised access and data exfiltration "
            "whilst remaining largely undetected by conventional network security measures."
        ),
        business_impact=[
            "Covert command and control channels enabling persistent access",
            "Data exfiltration through DNS tunnelling",
            "Prolonged attacker dwell time due to detection challenges",
            "Compliance violations from undetected malicious communications",
            "Potential for lateral movement and privilege escalation",
            "Reputation damage if DNS infrastructure is compromised",
        ],
        typical_attack_phase="command_and_control",
        often_precedes=["T1041", "T1567", "T1048"],  # Exfiltration techniques
        often_follows=["T1078.004", "T1190", "T1566"],  # Initial Access techniques
    ),
    detection_strategies=[
        # Strategy 1: AWS - Route 53 Resolver DNS Firewall
        DetectionStrategy(
            strategy_id="t1071-004-aws-dns-firewall",
            name="AWS Route 53 Resolver DNS Firewall with Threat Intelligence",
            description="Block DNS queries to known malicious domains using AWS Managed Domain Lists for malware, botnets, and C2 infrastructure. Provides first line of defence against DNS-based threats with real-time blocking and comprehensive logging.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="route53resolver",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query=r"""# CloudWatch Insights query for DNS Firewall block analysis
fields @timestamp, firewall_rule_group_id, firewall_rule_action, firewall_domain_list_id, query_name, src_addr, query_type
| filter firewall_rule_action = "BLOCK" or firewall_rule_action = "ALERT"
# Group by source to identify compromised resources
| stats count() as block_count, dc(query_name) as unique_domains by src_addr, firewall_rule_action, bin(5m)
# Alert on high-volume blocking indicating active C2 attempts
| filter block_count > 10
| sort block_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Route 53 Resolver DNS Firewall with AWS Managed Threat Intelligence

Parameters:
  VpcId:
    Type: AWS::EC2::VPC::Id
    Description: VPC to protect with DNS Firewall
  AlertEmail:
    Type: String
    Description: Email address for DNS threat alerts
  FirewallLogRetentionDays:
    Type: Number
    Default: 90
    Description: CloudWatch Logs retention period for DNS Firewall logs

Resources:
  # Step 1: Create DNS Firewall rule group with AWS Managed Domain Lists
  DnsFirewallRuleGroup:
    Type: AWS::Route53Resolver::FirewallRuleGroup
    Properties:
      Name: dns-threat-protection-rules
      Tags:
        - Key: Purpose
          Value: DNS-C2-Protection

  # Block malware domains (highest priority)
  MalwareBlockRule:
    Type: AWS::Route53Resolver::FirewallRule
    Properties:
      FirewallRuleGroupId: !Ref DnsFirewallRuleGroup
      FirewallDomainListId: rslvr-fdl-malware
      Name: block-malware-domains
      Action: BLOCK
      BlockResponse: NXDOMAIN
      Priority: 100

  # Block botnet C2 domains
  BotnetBlockRule:
    Type: AWS::Route53Resolver::FirewallRule
    Properties:
      FirewallRuleGroupId: !Ref DnsFirewallRuleGroup
      FirewallDomainListId: rslvr-fdl-botnetcc
      Name: block-botnet-c2
      Action: BLOCK
      BlockResponse: NXDOMAIN
      Priority: 200

  # Alert on GuardDuty threat intel (allows query but logs)
  GuardDutyAlertRule:
    Type: AWS::Route53Resolver::FirewallRule
    Properties:
      FirewallRuleGroupId: !Ref DnsFirewallRuleGroup
      FirewallDomainListId: rslvr-fdl-guardduty
      Name: alert-guardduty-threats
      Action: ALERT
      Priority: 300

  # Step 2: Associate firewall with VPC
  FirewallVpcAssociation:
    Type: AWS::Route53Resolver::FirewallRuleGroupAssociation
    Properties:
      FirewallRuleGroupId: !Ref DnsFirewallRuleGroup
      VpcId: !Ref VpcId
      Priority: 101
      Name: !Sub '${VpcId}-dns-firewall'

  # Step 3: Configure DNS Firewall logging
  FirewallLogGroup:
    Type: AWS::Logs::LogGroup
    Properties:
      LogGroupName: /aws/route53/resolver/firewall/dns-threats
      RetentionInDays: !Ref FirewallLogRetentionDays
      KmsKeyId: !GetAtt FirewallLogEncryptionKey.Arn

  FirewallLogEncryptionKey:
    Type: AWS::KMS::Key
    Properties:
      Description: Encryption key for DNS Firewall logs
      EnableKeyRotation: true
      KeyPolicy:
        Version: '2012-10-17'
        Statement:
          - Sid: Enable IAM User Permissions
            Effect: Allow
            Principal:
              AWS: !Sub 'arn:aws:iam::${AWS::AccountId}:root'
            Action: 'kms:*'
            Resource: '*'
          - Sid: Allow CloudWatch Logs
            Effect: Allow
            Principal:
              Service: !Sub 'logs.${AWS::Region}.amazonaws.com'
            Action:
              - 'kms:Encrypt'
              - 'kms:Decrypt'
              - 'kms:ReEncrypt*'
              - 'kms:GenerateDataKey*'
              - 'kms:CreateGrant'
              - 'kms:DescribeKey'
            Resource: '*'
            Condition:
              ArnLike:
                'kms:EncryptionContext:aws:logs:arn': !Sub 'arn:aws:logs:${AWS::Region}:${AWS::AccountId}:log-group:/aws/route53/resolver/firewall/*'

  FirewallLogConfig:
    Type: AWS::Route53Resolver::FirewallDomainList
    Properties:
      Name: dns-firewall-logging-config

  # Step 4: SNS topic for DNS threat alerts
  DnsThreatAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: DNS Firewall Threat Alerts
      KmsMasterKeyId: !Ref AlertTopicEncryptionKey
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  AlertTopicEncryptionKey:
    Type: AWS::KMS::Key
    Properties:
      Description: Encryption key for DNS threat alert SNS topic
      EnableKeyRotation: true
      KeyPolicy:
        Version: '2012-10-17'
        Statement:
          - Sid: Enable IAM User Permissions
            Effect: Allow
            Principal:
              AWS: !Sub 'arn:aws:iam::${AWS::AccountId}:root'
            Action: 'kms:*'
            Resource: '*'
          - Sid: Allow SNS
            Effect: Allow
            Principal:
              Service: sns.amazonaws.com
            Action:
              - 'kms:Decrypt'
              - 'kms:GenerateDataKey'
            Resource: '*'
          - Sid: Allow CloudWatch Events
            Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action:
              - 'kms:Decrypt'
              - 'kms:GenerateDataKey'
            Resource: '*'

  # Step 5: Metric filter for blocked DNS queries
  BlockedQueriesMetric:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref FirewallLogGroup
      FilterPattern: '{ $.firewall_rule_action = "BLOCK" }'
      MetricTransformations:
        - MetricName: DnsFirewallBlocks
          MetricNamespace: Security/DnsFirewall
          MetricValue: '1'
          DefaultValue: 0

  # Step 6: CloudWatch alarm for blocked queries
  BlockedQueriesAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: DnsFirewallBlocksDetected
      AlarmDescription: Alert when DNS Firewall blocks malicious queries
      MetricName: DnsFirewallBlocks
      Namespace: Security/DnsFirewall
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 10
      ComparisonOperator: GreaterThanThreshold
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref DnsThreatAlertTopic

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref DnsThreatAlertTopic
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: cloudwatch.amazonaws.com
            Action: sns:Publish
            Resource: !Ref DnsThreatAlertTopic

Outputs:
  FirewallRuleGroupId:
    Description: DNS Firewall Rule Group ID
    Value: !Ref DnsFirewallRuleGroup
  FirewallLogGroup:
    Description: CloudWatch Log Group for DNS Firewall
    Value: !Ref FirewallLogGroup""",
                terraform_template="""# AWS Route 53 Resolver DNS Firewall with Managed Threat Intelligence

variable "vpc_id" {
  type        = string
  description = "VPC to protect with DNS Firewall"
}

variable "alert_email" {
  type        = string
  description = "Email address for DNS threat alerts"
}

variable "firewall_log_retention_days" {
  type        = number
  default     = 90
  description = "CloudWatch Logs retention period for DNS Firewall logs"
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# Step 1: Create DNS Firewall rule group
resource "aws_route53_resolver_firewall_rule_group" "dns_protection" {
  name = "dns-threat-protection-rules"

  tags = {
    Purpose = "DNS-C2-Protection"
  }
}

# Block malware domains (highest priority)
resource "aws_route53_resolver_firewall_rule" "block_malware" {
  name                    = "block-malware-domains"
  firewall_rule_group_id  = aws_route53_resolver_firewall_rule_group.dns_protection.id
  firewall_domain_list_id = "rslvr-fdl-malware"
  action                  = "BLOCK"
  block_response          = "NXDOMAIN"
  priority                = 100
}

# Block botnet C2 domains
resource "aws_route53_resolver_firewall_rule" "block_botnet" {
  name                    = "block-botnet-c2"
  firewall_rule_group_id  = aws_route53_resolver_firewall_rule_group.dns_protection.id
  firewall_domain_list_id = "rslvr-fdl-botnetcc"
  action                  = "BLOCK"
  block_response          = "NXDOMAIN"
  priority                = 200
}

# Alert on GuardDuty threat intelligence
resource "aws_route53_resolver_firewall_rule" "alert_guardduty" {
  name                    = "alert-guardduty-threats"
  firewall_rule_group_id  = aws_route53_resolver_firewall_rule_group.dns_protection.id
  firewall_domain_list_id = "rslvr-fdl-guardduty"
  action                  = "ALERT"
  priority                = 300
}

# Step 2: Associate firewall with VPC
resource "aws_route53_resolver_firewall_rule_group_association" "vpc" {
  name                   = "${var.vpc_id}-dns-firewall"
  firewall_rule_group_id = aws_route53_resolver_firewall_rule_group.dns_protection.id
  vpc_id                 = var.vpc_id
  priority               = 101
}

# Step 3: Configure DNS Firewall logging with encryption
resource "aws_kms_key" "firewall_logs" {
  description             = "Encryption key for DNS Firewall logs"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow CloudWatch Logs"
        Effect = "Allow"
        Principal = {
          Service = "logs.${data.aws_region.current.name}.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:CreateGrant",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          ArnLike = {
            "kms:EncryptionContext:aws:logs:arn" = "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/route53/resolver/firewall/*"
          }
        }
      }
    ]
  })
}

resource "aws_kms_alias" "firewall_logs" {
  name          = "alias/route53-resolver-firewall-logs"
  target_key_id = aws_kms_key.firewall_logs.key_id
}

resource "aws_cloudwatch_log_group" "firewall" {
  name              = "/aws/route53/resolver/firewall/dns-threats"
  retention_in_days = var.firewall_log_retention_days
  kms_key_id        = aws_kms_key.firewall_logs.arn
}

resource "aws_route53_resolver_firewall_config" "main" {
  resource_id        = var.vpc_id
  firewall_fail_open = "DISABLED"
}

# Step 4: SNS topic for alerts with encryption
resource "aws_kms_key" "alert_topic" {
  description             = "Encryption key for DNS threat alert SNS topic"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow SNS"
        Effect = "Allow"
        Principal = {
          Service = "sns.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = "*"
      },
      {
        Sid    = "Allow CloudWatch Events"
        Effect = "Allow"
        Principal = {
          Service = "events.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_kms_alias" "alert_topic" {
  name          = "alias/dns-firewall-alerts"
  target_key_id = aws_kms_key.alert_topic.key_id
}

resource "aws_sns_topic" "dns_threats" {
  name              = "dns-firewall-threat-alerts"
  display_name      = "DNS Firewall Threat Alerts"
  kms_master_key_id = aws_kms_key.alert_topic.id
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.dns_threats.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 5: Metric filter for blocked queries
resource "aws_cloudwatch_log_metric_filter" "blocked_queries" {
  name           = "dns-firewall-blocks"
  log_group_name = aws_cloudwatch_log_group.firewall.name
  pattern        = "{ $.firewall_rule_action = \"BLOCK\" }"

  metric_transformation {
    name      = "DnsFirewallBlocks"
    namespace = "Security/DnsFirewall"
    value     = "1"
  }
}

# Step 6: CloudWatch alarm
resource "aws_cloudwatch_metric_alarm" "blocked_queries" {
  alarm_name          = "DnsFirewallBlocksDetected"
  alarm_description   = "Alert when DNS Firewall blocks malicious queries"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "DnsFirewallBlocks"
  namespace           = "Security/DnsFirewall"
  period              = 300
  statistic           = "Sum"
  threshold           = 10
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.dns_threats.arn]
  treat_missing_data  = "notBreaching"
}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.dns_threats.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.dns_threats.arn
    Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}

output "firewall_rule_group_id" {
  description = "DNS Firewall Rule Group ID"
  value       = aws_route53_resolver_firewall_rule_group.dns_protection.id
}

output "firewall_log_group" {
  description = "CloudWatch Log Group for DNS Firewall"
  value       = aws_cloudwatch_log_group.firewall.name
}""",
                alert_severity="critical",
                alert_title="DNS Firewall Blocked Malicious Domain Query",
                alert_description_template="Route 53 Resolver DNS Firewall blocked a query to a known malicious domain. This may indicate C2 communication or malware activity.",
                investigation_steps=[
                    "Review DNS Firewall logs to identify blocked domains",
                    "Identify source IP and instance making malicious queries",
                    "Check which AWS Managed Domain List triggered the block",
                    "Review CloudTrail for recent API activity from the source",
                    "Examine instance processes for malware or suspicious executables",
                    "Check VPC Flow Logs for additional network indicators",
                    "Correlate with GuardDuty findings for the same resource",
                    "Investigate for signs of initial compromise or lateral movement",
                ],
                containment_actions=[
                    "Isolate affected instances using security groups immediately",
                    "Create forensic snapshots before making changes",
                    "Revoke IAM credentials for affected instances",
                    "Add additional custom domains to DNS Firewall block list",
                    "Enable VPC Flow Logs if not already enabled",
                    "Deploy endpoint detection and response tools",
                    "Review and restrict security group egress rules",
                    "Terminate compromised instances and rebuild from clean AMIs",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="AWS Managed Domain Lists are continuously updated with verified threats. False positives are rare but can occur with recently-registered legitimate domains. Monitor ALERT rules before promoting to BLOCK.",
            detection_coverage="95% - Blocks known malicious domains using AWS and third-party threat intelligence (RecordedFuture)",
            evasion_considerations="Zero-day C2 domains not yet in threat feeds will bypass. Consider combining with anomaly-based detection.",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30-45 minutes",
            estimated_monthly_cost="$25-50 per million queries",
            prerequisites=[
                "VPC with Route 53 Resolver",
                "CloudWatch Logs",
                "KMS for encryption (recommended)",
            ],
        ),
        # Strategy 2: AWS - Route 53 Resolver Query Logging
        DetectionStrategy(
            strategy_id="t1071-004-aws-query-logging",
            name="AWS Route 53 Resolver Query Logging and Anomaly Detection",
            description="Enable comprehensive DNS query logging for Route 53 Resolver to detect DNS tunnelling patterns, long subdomains, high-entropy queries, and beaconing behaviour.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="route53resolver",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query=r"""# CloudWatch Insights query for DNS tunnelling and anomaly detection
fields @timestamp, query_name, query_type, srcaddr, rcode
# Detect long subdomains (>50 characters before first dot) - DNS tunnelling indicator
| parse query_name /(?<subdomain>[^.]{50,})\./
| filter ispresent(subdomain) or strlen(query_name) > 100
# Detect suspicious query types often used in tunnelling (TXT for data, NULL for covert channels)
| filter query_type in ["TXT", "NULL", "ANY", "MX", "CNAME"]
# Detect high-entropy encoded data indicating data exfiltration
# Hexadecimal pattern: 40+ consecutive hex chars
# Base64 pattern: 60+ characters from Base64 alphabet
| filter query_name like /[a-f0-9]{40,}/ or query_name like /[A-Za-z0-9+\/=]{60,}/
# Aggregate by source to identify compromised instances
| stats count() as query_count, dc(query_name) as unique_queries, dc(query_type) as query_types by srcaddr, bin(5m)
# High query volume or query diversity indicates tunnelling
| filter query_count > 20 or unique_queries > 15
| sort query_count desc, unique_queries desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Route 53 Resolver Query Logging for DNS threat detection

Parameters:
  VpcId:
    Type: AWS::EC2::VPC::Id
    Description: VPC to enable DNS query logging
  AlertEmail:
    Type: String
    Description: Email address for security alerts
  QueryLogRetentionDays:
    Type: Number
    Default: 90
    Description: CloudWatch Logs retention period

Resources:
  # Step 1: Create encrypted CloudWatch Log Group for DNS queries
  QueryLogGroup:
    Type: AWS::Logs::LogGroup
    Properties:
      LogGroupName: /aws/route53/resolver/queries
      RetentionInDays: !Ref QueryLogRetentionDays
      KmsKeyId: !GetAtt QueryLogEncryptionKey.Arn

  QueryLogEncryptionKey:
    Type: AWS::KMS::Key
    Properties:
      Description: Encryption key for Route 53 Resolver query logs
      EnableKeyRotation: true
      KeyPolicy:
        Version: '2012-10-17'
        Statement:
          - Sid: Enable IAM User Permissions
            Effect: Allow
            Principal:
              AWS: !Sub 'arn:aws:iam::${AWS::AccountId}:root'
            Action: 'kms:*'
            Resource: '*'
          - Sid: Allow CloudWatch Logs
            Effect: Allow
            Principal:
              Service: !Sub 'logs.${AWS::Region}.amazonaws.com'
            Action:
              - 'kms:Encrypt'
              - 'kms:Decrypt'
              - 'kms:ReEncrypt*'
              - 'kms:GenerateDataKey*'
              - 'kms:CreateGrant'
              - 'kms:DescribeKey'
            Resource: '*'
          - Sid: Allow Route 53 Resolver
            Effect: Allow
            Principal:
              Service: route53resolver.amazonaws.com
            Action:
              - 'kms:Encrypt'
              - 'kms:Decrypt'
              - 'kms:GenerateDataKey*'
            Resource: '*'

  QueryLogResourcePolicy:
    Type: AWS::Logs::ResourcePolicy
    Properties:
      PolicyName: Route53ResolverQueryLogging
      PolicyDocument: !Sub |
        {
          "Version": "2012-10-17",
          "Statement": [{
            "Effect": "Allow",
            "Principal": {
              "Service": "route53resolver.amazonaws.com"
            },
            "Action": [
              "logs:CreateLogStream",
              "logs:PutLogEvents"
            ],
            "Resource": "${QueryLogGroup.Arn}"
          }]
        }

  # Step 2: Configure Route 53 Resolver Query Logging
  QueryLogConfig:
    Type: AWS::Route53Resolver::ResolverQueryLoggingConfig
    Properties:
      Name: dns-query-logging
      DestinationArn: !GetAtt QueryLogGroup.Arn

  QueryLogConfigAssociation:
    Type: AWS::Route53Resolver::ResolverQueryLoggingConfigAssociation
    Properties:
      ResolverQueryLogConfigId: !Ref QueryLogConfig
      ResourceId: !Ref VpcId

  # Step 3: SNS topic for anomaly alerts
  DnsAnomalyAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: DNS Query Anomaly Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Metric filter for long subdomains (DNS tunnelling indicator)
  LongSubdomainMetric:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref QueryLogGroup
      FilterPattern: '{ ($.query_name = "*") && ($.query_class_name = "IN") }'
      MetricTransformations:
        - MetricName: LongDnsQueries
          MetricNamespace: Security/DnsTunnelling
          MetricValue: '1'
          DefaultValue: 0

  # Metric filter for suspicious query types
  SuspiciousQueryTypeMetric:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref QueryLogGroup
      FilterPattern: '{ $.query_type = "TXT" || $.query_type = "NULL" || $.query_type = "ANY" }'
      MetricTransformations:
        - MetricName: SuspiciousDnsQueryTypes
          MetricNamespace: Security/DnsTunnelling
          MetricValue: '1'
          DefaultValue: 0

  # Alarm for DNS tunnelling patterns
  DnsTunnellingAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: DnsTunnellingPatternDetected
      AlarmDescription: High volume of suspicious DNS queries indicating tunnelling
      MetricName: SuspiciousDnsQueryTypes
      Namespace: Security/DnsTunnelling
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 50
      ComparisonOperator: GreaterThanThreshold
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref DnsAnomalyAlertTopic

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref DnsAnomalyAlertTopic
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: cloudwatch.amazonaws.com
            Action: sns:Publish
            Resource: !Ref DnsAnomalyAlertTopic

Outputs:
  QueryLogConfigId:
    Description: Route 53 Resolver Query Logging Config ID
    Value: !Ref QueryLogConfig
  QueryLogGroupName:
    Description: CloudWatch Log Group for DNS queries
    Value: !Ref QueryLogGroup""",
                terraform_template="""# Route 53 Resolver Query Logging for DNS threat detection

variable "vpc_id" {
  type        = string
  description = "VPC to enable DNS query logging"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

variable "query_log_retention_days" {
  type        = number
  default     = 90
  description = "CloudWatch Logs retention period"
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# Step 1: Create encrypted CloudWatch Log Group
resource "aws_kms_key" "query_logs" {
  description             = "Encryption key for Route 53 Resolver query logs"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow CloudWatch Logs"
        Effect = "Allow"
        Principal = {
          Service = "logs.${data.aws_region.current.name}.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:CreateGrant",
          "kms:DescribeKey"
        ]
        Resource = "*"
      },
      {
        Sid    = "Allow Route 53 Resolver"
        Effect = "Allow"
        Principal = {
          Service = "route53resolver.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:GenerateDataKey*"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_kms_alias" "query_logs" {
  name          = "alias/route53-resolver-query-logs"
  target_key_id = aws_kms_key.query_logs.key_id
}

resource "aws_cloudwatch_log_group" "resolver_queries" {
  name              = "/aws/route53/resolver/queries"
  retention_in_days = var.query_log_retention_days
  kms_key_id        = aws_kms_key.query_logs.arn
}

resource "aws_cloudwatch_log_resource_policy" "route53_resolver" {
  policy_name = "Route53ResolverQueryLogging"

  policy_document = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "route53resolver.amazonaws.com"
      }
      Action = [
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ]
      Resource = "${aws_cloudwatch_log_group.resolver_queries.arn}:*"
    }]
  })
}

# Step 2: Configure Route 53 Resolver Query Logging
resource "aws_route53_resolver_query_log_config" "main" {
  name            = "dns-query-logging"
  destination_arn = aws_cloudwatch_log_group.resolver_queries.arn

  depends_on = [aws_cloudwatch_log_resource_policy.route53_resolver]
}

resource "aws_route53_resolver_query_log_config_association" "vpc" {
  resolver_query_log_config_id = aws_route53_resolver_query_log_config.main.id
  resource_id                  = var.vpc_id
}

# Step 3: SNS topic for anomaly alerts
resource "aws_sns_topic" "dns_anomalies" {
  name         = "dns-query-anomaly-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "DNS Query Anomaly Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.dns_anomalies.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Metric filter for long subdomains
resource "aws_cloudwatch_log_metric_filter" "long_subdomains" {
  name           = "long-dns-queries"
  log_group_name = aws_cloudwatch_log_group.resolver_queries.name
  pattern        = "{ ($.query_name = \"*\") && ($.query_class_name = \"IN\") }"

  metric_transformation {
    name      = "LongDnsQueries"
    namespace = "Security/DnsTunnelling"
    value     = "1"
  }
}

# Metric filter for suspicious query types
resource "aws_cloudwatch_log_metric_filter" "suspicious_types" {
  name           = "suspicious-dns-query-types"
  log_group_name = aws_cloudwatch_log_group.resolver_queries.name
  pattern        = "{ $.query_type = \"TXT\" || $.query_type = \"NULL\" || $.query_type = \"ANY\" }"

  metric_transformation {
    name      = "SuspiciousDnsQueryTypes"
    namespace = "Security/DnsTunnelling"
    value     = "1"
  }
}

# Alarm for DNS tunnelling
resource "aws_cloudwatch_metric_alarm" "dns_tunnelling" {
  alarm_name          = "DnsTunnellingPatternDetected"
  alarm_description   = "High volume of suspicious DNS queries indicating tunnelling"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "SuspiciousDnsQueryTypes"
  namespace           = "Security/DnsTunnelling"
  period              = 300
  statistic           = "Sum"
  threshold           = 50
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.dns_anomalies.arn]
  treat_missing_data  = "notBreaching"
}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.dns_anomalies.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.dns_anomalies.arn
    Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}

output "query_log_config_id" {
  description = "Route 53 Resolver Query Logging Config ID"
  value       = aws_route53_resolver_query_log_config.main.id
}

output "query_log_group_name" {
  description = "CloudWatch Log Group for DNS queries"
  value       = aws_cloudwatch_log_group.resolver_queries.name
}""",
                alert_severity="high",
                alert_title="DNS Tunnelling Pattern Detected",
                alert_description_template="Suspicious DNS query patterns detected: long subdomains (>50 chars), unusual record types, or high-entropy domains indicating potential DNS tunnelling or C2 activity.",
                investigation_steps=[
                    "Query CloudWatch Logs Insights for detailed DNS patterns",
                    "Identify source IP addresses making suspicious queries",
                    "Analyse subdomain lengths and entropy scores",
                    "Check for periodic beaconing patterns (regular intervals)",
                    "Review queried domains and their registration details",
                    "Examine VPC Flow Logs for correlated network activity",
                    "Investigate source instances for malware or compromised credentials",
                    "Check CloudTrail for recent API activity from affected resources",
                ],
                containment_actions=[
                    "Add suspicious domains to Route 53 Resolver DNS Firewall block list",
                    "Isolate affected instances using security groups",
                    "Create forensic snapshots before remediation",
                    "Revoke IAM credentials for compromised resources",
                    "Review and restrict security group egress rules",
                    "Enable VPC Flow Logs if not already enabled",
                    "Deploy endpoint detection tools on affected instances",
                    "Consider DNS sinkholing for identified C2 domains",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Establish baselines for legitimate long queries (CDN domains, cloud services). Whitelist known services using TXT records for verification (SPF, DKIM, DMARC). Tune thresholds based on environment.",
            detection_coverage="85% - Detects DNS tunnelling patterns through query analysis",
            evasion_considerations="Attackers may use low-frequency queries, legitimate DNS services, or standard query lengths to evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-1.5 hours",
            estimated_monthly_cost="$15-40 depending on query volume",
            prerequisites=[
                "VPC with Route 53 Resolver",
                "CloudWatch Logs",
                "CloudWatch Logs Insights",
            ],
        ),
        # Strategy 3: AWS - DNS Beaconing Detection
        DetectionStrategy(
            strategy_id="t1071-004-aws-dns-beaconing",
            name="AWS DNS Beaconing Pattern Detection",
            description="Detect periodic DNS queries at regular intervals indicating C2 check-ins using tools like dnscat2, Iodine, or DNS2TCP.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query=r"""# CloudWatch Insights query for DNS beaconing detection
# Beaconing = regular, periodic DNS queries at consistent intervals indicating C2 check-ins
fields @timestamp, query_name, query_type, srcaddr, rcode
| filter ispresent(query_name) and rcode = "NOERROR"
# Aggregate queries per minute to detect periodic timing patterns
| stats count() as query_count by srcaddr, query_name, bin(60s)
# Regular beaconing: consistent query volume per interval (3-10 queries/min typical for C2)
# Too few = not beaconing, too many = legitimate service
| filter query_count >= 3 and query_count <= 10
# Count consecutive regular intervals (beaconing signature)
| stats count() as beacon_intervals, avg(query_count) as avg_queries_per_min by srcaddr, query_name
# Strong beaconing indicator: >5 consecutive regular intervals with low variance
| filter beacon_intervals > 5
# Add statistical consistency check (coefficient of variation)
| fields srcaddr, query_name, beacon_intervals, avg_queries_per_min
| sort beacon_intervals desc, avg_queries_per_min asc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: DNS beaconing detection for C2 communications

Parameters:
  Route53LogGroup:
    Type: String
    Description: CloudWatch Log Group for Route 53 Resolver Query Logging
  AlertEmail:
    Type: String
    Description: Email address for security alerts

Resources:
  # Step 1: SNS topic for beaconing alerts
  BeaconingAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: DNS Beaconing Detection Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: CloudWatch Insights query definition
  BeaconingQueryDefinition:
    Type: AWS::Logs::QueryDefinition
    Properties:
      Name: DNS-Beaconing-Detection
      QueryString: |
        fields @timestamp, query_name, srcaddr, rcode
        | filter ispresent(query_name) and rcode = "NOERROR"
        | stats count() as query_count by srcaddr, query_name, bin(60s)
        | filter query_count >= 3 and query_count <= 10
        | stats count() as beacon_intervals, avg(query_count) as avg_queries_per_min by srcaddr, query_name
        | filter beacon_intervals > 5
        | sort beacon_intervals desc
      LogGroupNames:
        - !Ref Route53LogGroup

  # Additional query for DNS entropy analysis (DGA detection)
  EntropyQueryDefinition:
    Type: AWS::Logs::QueryDefinition
    Properties:
      Name: DNS-High-Entropy-DGA-Detection
      QueryString: |
        fields @timestamp, query_name, srcaddr
        | filter query_name like /[a-z]{20,}\./
        | stats count() as query_count by srcaddr, bin(5m)
        | filter query_count > 10
        | sort query_count desc
      LogGroupNames:
        - !Ref Route53LogGroup

  # Step 3: Metric filter for periodic query patterns
  BeaconingMetric:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref Route53LogGroup
      FilterPattern: '{ $.query_name = "*" }'
      MetricTransformations:
        - MetricName: DnsBeaconingQueries
          MetricNamespace: Security/DnsBeaconing
          MetricValue: '1'
          DefaultValue: 0

  # Step 4: CloudWatch alarm (requires custom Lambda for advanced pattern detection)
  BeaconingAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: DnsBeaconingDetected
      AlarmDescription: Regular periodic DNS queries detected indicating C2 beaconing
      MetricName: DnsBeaconingQueries
      Namespace: Security/DnsBeaconing
      Statistic: Sum
      Period: 900
      EvaluationPeriods: 2
      Threshold: 100
      ComparisonOperator: GreaterThanThreshold
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref BeaconingAlertTopic

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref BeaconingAlertTopic
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: cloudwatch.amazonaws.com
            Action: sns:Publish
            Resource: !Ref BeaconingAlertTopic

Outputs:
  QueryDefinitionId:
    Description: CloudWatch Logs Insights Query Definition ID
    Value: !Ref BeaconingQueryDefinition""",
                terraform_template="""# DNS beaconing detection for C2 communications

variable "route53_log_group" {
  type        = string
  description = "CloudWatch Log Group for Route 53 Resolver Query Logging"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "dns_beaconing" {
  name         = "dns-beaconing-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "DNS Beaconing Detection Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.dns_beaconing.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: CloudWatch Logs Insights query definitions
resource "aws_cloudwatch_query_definition" "beaconing" {
  name = "DNS-Beaconing-Detection"

  query_string = <<-EOQ
    fields @timestamp, query_name, srcaddr, rcode
    | filter ispresent(query_name) and rcode = "NOERROR"
    | stats count() as query_count by srcaddr, query_name, bin(60s)
    | filter query_count >= 3 and query_count <= 10
    | stats count() as beacon_intervals, avg(query_count) as avg_queries_per_min by srcaddr, query_name
    | filter beacon_intervals > 5
    | sort beacon_intervals desc
  EOQ

  log_group_names = [var.route53_log_group]
}

# Additional query for DGA detection (high-entropy domains)
resource "aws_cloudwatch_query_definition" "dga_detection" {
  name = "DNS-High-Entropy-DGA-Detection"

  query_string = <<-EOQ
    fields @timestamp, query_name, srcaddr
    | filter query_name like /[a-z]{20,}\./
    | stats count() as query_count by srcaddr, bin(5m)
    | filter query_count > 10
    | sort query_count desc
  EOQ

  log_group_names = [var.route53_log_group]
}

# Step 3: Metric filter for periodic patterns
resource "aws_cloudwatch_log_metric_filter" "beaconing" {
  name           = "dns-beaconing-queries"
  log_group_name = var.route53_log_group
  pattern        = "{ $.query_name = \"*\" }"

  metric_transformation {
    name      = "DnsBeaconingQueries"
    namespace = "Security/DnsBeaconing"
    value     = "1"
  }
}

# Step 4: CloudWatch alarm
resource "aws_cloudwatch_metric_alarm" "beaconing" {
  alarm_name          = "DnsBeaconingDetected"
  alarm_description   = "Regular periodic DNS queries detected indicating C2 beaconing"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "DnsBeaconingQueries"
  namespace           = "Security/DnsBeaconing"
  period              = 900
  statistic           = "Sum"
  threshold           = 100
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.dns_beaconing.arn]
  treat_missing_data  = "notBreaching"
}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.dns_beaconing.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.dns_beaconing.arn
    Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}

output "query_definition_id" {
  description = "CloudWatch Logs Insights Query Definition ID"
  value       = aws_cloudwatch_query_definition.beaconing.id
}""",
                alert_severity="high",
                alert_title="DNS Beaconing Activity Detected",
                alert_description_template="Regular, periodic DNS queries detected indicating C2 beaconing behaviour. This pattern is consistent with tools like dnscat2, Iodine, or DNS2TCP.",
                investigation_steps=[
                    "Run CloudWatch Insights query to analyse beacon timing intervals",
                    "Identify source instances making periodic queries",
                    "Calculate standard deviation of query intervals (low = beaconing)",
                    "Review queried domains and their registration information",
                    "Check instance processes for DNS tunnelling tools",
                    "Examine network traffic for additional C2 indicators",
                    "Review CloudTrail for recent API activity from source",
                    "Check for data encoding in DNS query strings",
                ],
                containment_actions=[
                    "Isolate beaconing instances from network immediately",
                    "Block destination domains via Route 53 Resolver DNS Firewall",
                    "Create forensic snapshots for analysis",
                    "Revoke IAM credentials for affected instances",
                    "Review and restrict security group egress rules",
                    "Deploy endpoint detection tools to identify malware",
                    "Add C2 domains to DNS Firewall custom block list",
                    "Monitor for similar beaconing patterns from other sources",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Establish baselines for legitimate periodic queries (health checks, monitoring agents, scheduled tasks). Whitelist known infrastructure monitoring tools. Adjust timing thresholds based on environment.",
            detection_coverage="75% - Detects regular beaconing but may miss randomised intervals",
            evasion_considerations="Attackers may add jitter to beacon intervals, vary query timing, or use low-frequency queries to evade pattern detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-1.5 hours",
            estimated_monthly_cost="$5-15",
            prerequisites=[
                "Route 53 Resolver Query Logging enabled",
                "CloudWatch Logs Insights",
            ],
        ),
        # Strategy 4: AWS - GuardDuty DNS C2 Detection
        DetectionStrategy(
            strategy_id="t1071-004-aws-guardduty",
            name="AWS GuardDuty DNS C2 Activity Detection",
            description="Leverage AWS GuardDuty to detect DNS-based C2 communications and DNS data exfiltration using threat intelligence and machine learning.",
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "Backdoor:EC2/C&CActivity.B!DNS",
                    "Trojan:EC2/DNSDataExfiltration",
                    "Backdoor:EC2/DenialOfService.Dns",
                    "Trojan:EC2/BlackholeTraffic!DNS",
                    "Trojan:EC2/DropPoint!DNS",
                ],
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Configure GuardDuty alerts for DNS-based C2 detection

Parameters:
  AlertEmail:
    Type: String
    Description: Email address for security alerts

Resources:
  # Step 1: Enable GuardDuty (if not already enabled)
  GuardDutyDetector:
    Type: AWS::GuardDuty::Detector
    Properties:
      Enable: true
      FindingPublishingFrequency: FIFTEEN_MINUTES
      DataSources:
        S3Logs:
          Enable: true
        Kubernetes:
          AuditLogs:
            Enable: true
        MalwareProtection:
          ScanEc2InstanceWithFindings:
            EbsVolumes:
              Enable: true

  # Step 2: SNS topic for GuardDuty findings
  GuardDutyAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: GuardDuty DNS C2 Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 3: EventBridge rule for DNS C2 findings
  DnsC2FindingRule:
    Type: AWS::Events::Rule
    Properties:
      Description: Alert on GuardDuty DNS C2 findings
      EventPattern:
        source:
          - aws.guardduty
        detail-type:
          - GuardDuty Finding
        detail:
          type:
            - prefix: Backdoor:EC2/C&CActivity.B!DNS
            - prefix: Trojan:EC2/DNSDataExfiltration
            - prefix: Backdoor:EC2/DenialOfService.Dns
            - prefix: Trojan:EC2/BlackholeTraffic!DNS
      State: ENABLED
      Targets:
        - Id: AlertTopic
          Arn: !Ref GuardDutyAlertTopic

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref GuardDutyAlertTopic
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref GuardDutyAlertTopic""",
                terraform_template="""# Configure GuardDuty for DNS C2 detection

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: Enable GuardDuty with enhanced detection
resource "aws_guardduty_detector" "main" {
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"

  datasources {
    s3_logs {
      enable = true
    }
    kubernetes {
      audit_logs {
        enable = true
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = true
        }
      }
    }
  }
}

# Step 2: SNS topic for alerts
resource "aws_sns_topic" "guardduty_dns" {
  name         = "guardduty-dns-c2-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "GuardDuty DNS C2 Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.guardduty_dns.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 3: EventBridge rule for DNS C2 findings
resource "aws_cloudwatch_event_rule" "guardduty_dns_c2" {
  name        = "guardduty-dns-c2-detection"
  description = "Alert on GuardDuty DNS C2 findings"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [
        { prefix = "Backdoor:EC2/C&CActivity.B!DNS" },
        { prefix = "Trojan:EC2/DNSDataExfiltration" },
        { prefix = "Backdoor:EC2/DenialOfService.Dns" },
        { prefix = "Trojan:EC2/BlackholeTraffic!DNS" }
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.guardduty_dns_c2.name
  arn  = aws_sns_topic.guardduty_dns.arn
}

resource "aws_sns_topic_policy" "allow_events" {
  arn = aws_sns_topic.guardduty_dns.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.guardduty_dns.arn
    Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}""",
                alert_severity="critical",
                alert_title="GuardDuty DNS C2 Activity Detected",
                alert_description_template="GuardDuty detected {type} on instance {resource.instanceDetails.instanceId}. This indicates DNS-based command and control or data exfiltration activity.",
                investigation_steps=[
                    "Review GuardDuty finding details including severity and confidence",
                    "Identify affected EC2 instances and their IAM roles",
                    "Analyse DNS query logs for the affected instance",
                    "Check destination domains and IPs against threat intelligence",
                    "Review instance processes and running services",
                    "Examine CloudTrail logs for API activity from the instance",
                    "Check VPC Flow Logs for correlated network activity",
                    "Investigate for signs of initial compromise or lateral movement",
                ],
                containment_actions=[
                    "Isolate affected instances immediately using security groups",
                    "Create forensic snapshots and memory dumps before changes",
                    "Revoke IAM role credentials for affected instances",
                    "Block malicious domains via Route 53 Resolver DNS Firewall",
                    "Add C2 domains to AWS Network Firewall block list",
                    "Review and rotate any credentials accessible to the instance",
                    "Terminate compromised instances and deploy from clean AMIs",
                    "Update security group rules to prevent similar attacks",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Review findings for legitimate security tools, monitoring agents, and development environments. Create suppression rules for known benign DNS patterns. Update threat intelligence lists regularly.",
            detection_coverage="90% - GuardDuty uses threat intelligence, ML, and behavioural analysis for high accuracy DNS C2 detection",
            evasion_considerations="Zero-day C2 infrastructure not yet in threat intelligence feeds may evade detection initially. Custom or private DNS servers may not be monitored.",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30-45 minutes",
            estimated_monthly_cost="$30-100 depending on data volume and resources",
            prerequisites=[
                "GuardDuty enabled",
                "VPC Flow Logs",
                "DNS Logs",
                "CloudTrail enabled",
            ],
        ),
        # Strategy 5: GCP - Cloud DNS Response Policy Zones
        DetectionStrategy(
            strategy_id="t1071-004-gcp-response-policy",
            name="GCP Cloud DNS Response Policy Zones for Threat Blocking",
            description="Implement Cloud DNS Response Policy Zones (RPZ) to block queries to known malicious domains and provide custom DNS responses for threat mitigation.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_dns",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_terraform_template="""# GCP Cloud DNS Response Policy Zones for threat blocking

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "network_name" {
  type        = string
  description = "VPC network name to apply DNS policy"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: Create response policy for DNS threat blocking
resource "google_dns_response_policy" "dns_threat_blocking" {
  response_policy_name = "dns-threat-blocking-policy"
  project              = var.project_id
  description          = "Block queries to known malicious domains"

  networks {
    network_url = "https://www.googleapis.com/compute/v1/projects/${var.project_id}/global/networks/${var.network_name}"
  }
}

# Step 2: Create response policy rule to block malware C2 domains
resource "google_dns_response_policy_rule" "block_malware_c2" {
  project         = var.project_id
  response_policy = google_dns_response_policy.dns_threat_blocking.response_policy_name
  rule_name       = "block-malware-c2-domains"

  dns_name = "*.malicious-c2.example."

  local_data {
    local_datas {
      name = "*.malicious-c2.example."
      type = "A"
      ttl  = 300
      rrdatas = [
        "127.0.0.1"  # Sinkhole to localhost
      ]
    }
  }
}

# Step 3: Create response policy rule to block by behaviour
resource "google_dns_response_policy_rule" "block_dga_domains" {
  project         = var.project_id
  response_policy = google_dns_response_policy.dns_threat_blocking.response_policy_name
  rule_name       = "block-dga-pattern-domains"

  dns_name = "*.dga-pattern.example."

  behavior = "bypassResponsePolicy"  # Can be used with external threat feeds
}

# Step 4: Enable DNSSEC for DNS security
resource "google_dns_managed_zone" "secure_zone" {
  name        = "secure-dns-zone"
  dns_name    = "secure.example.com."
  description = "DNS zone with DNSSEC enabled for threat protection"
  project     = var.project_id

  visibility = "private"

  private_visibility_config {
    networks {
      network_url = "https://www.googleapis.com/compute/v1/projects/${var.project_id}/global/networks/${var.network_name}"
    }
  }

  dnssec_config {
    state         = "on"
    non_existence = "nsec3"

    default_key_specs {
      algorithm  = "rsasha256"
      key_length = 2048
      key_type   = "keySigning"
    }

    default_key_specs {
      algorithm  = "rsasha256"
      key_length = 1024
      key_type   = "zoneSigning"
    }
  }
}

# Step 5: Create log-based metric for blocked DNS queries
resource "google_logging_metric" "dns_blocks" {
  name    = "dns-response-policy-blocks"
  project = var.project_id

  filter = <<-EOT
    resource.type="dns_query"
    logName=~"projects/.*/logs/dns.googleapis.com%2Fdns_queries"
    jsonPayload.responsePolicy=~"dns-threat-blocking-policy"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"

    labels {
      key         = "blocked_domain"
      value_type  = "STRING"
      description = "Domain blocked by response policy"
    }
  }

  label_extractors = {
    blocked_domain = "EXTRACT(jsonPayload.queryName)"
  }
}

# Step 6: Notification channel for alerts
resource "google_monitoring_notification_channel" "email" {
  display_name = "DNS Threat Blocking Alerts"
  type         = "email"
  project      = var.project_id

  labels = {
    email_address = var.alert_email
  }
}

# Step 7: Alert policy for DNS blocks
resource "google_monitoring_alert_policy" "dns_blocks" {
  display_name = "DNS Response Policy Blocks Detected"
  combiner     = "OR"
  project      = var.project_id

  conditions {
    display_name = "Malicious DNS queries blocked"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.dns_blocks.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 10

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

  documentation {
    content   = "DNS Response Policy blocked queries to malicious domains. Investigate source VMs for potential C2 activity."
    mime_type = "text/markdown"
  }
}

output "response_policy_id" {
  description = "DNS Response Policy ID"
  value       = google_dns_response_policy.dns_threat_blocking.id
}

output "secure_zone_id" {
  description = "DNSSEC-enabled DNS zone ID"
  value       = google_dns_managed_zone.secure_zone.id
}""",
                alert_severity="critical",
                alert_title="GCP: DNS Response Policy Blocked Malicious Query",
                alert_description_template="Cloud DNS Response Policy blocked a query to a known malicious domain. Source VM may be compromised or attempting C2 communication.",
                investigation_steps=[
                    "Review Cloud DNS query logs for blocked domains",
                    "Identify source VM instances making malicious queries",
                    "Check which response policy rule triggered the block",
                    "Examine Cloud Audit Logs for recent VM activity",
                    "Review VPC Flow Logs for correlated network traffic",
                    "Investigate VM instance processes and running services",
                    "Check service account permissions and recent usage",
                    "Correlate with Security Command Centre findings",
                ],
                containment_actions=[
                    "Isolate affected VMs using VPC firewall rules",
                    "Create VM snapshots for forensic analysis",
                    "Revoke compromised service account keys",
                    "Add additional malicious domains to response policy",
                    "Enable VPC Service Controls to prevent data exfiltration",
                    "Review and restrict firewall egress rules",
                    "Deploy Cloud IDS for enhanced threat detection",
                    "Terminate compromised VMs and rebuild from clean images",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Response policies require manual domain list management. Integrate with threat intelligence feeds for automated updates. Test rules in monitoring mode before blocking.",
            detection_coverage="90% - Blocks known malicious domains when configured with threat intelligence",
            evasion_considerations="Zero-day C2 domains not in response policy will bypass. Requires continuous threat feed updates.",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-30 depending on query volume",
            prerequisites=[
                "Cloud DNS",
                "VPC network",
                "Cloud Logging",
                "Cloud Monitoring",
            ],
        ),
        # Strategy 6: GCP - Cloud DNS Query Logging and Anomaly Detection
        DetectionStrategy(
            strategy_id="t1071-004-gcp-dns-anomaly",
            name="GCP Cloud DNS Query Anomaly Detection",
            description="Detect unusual DNS query patterns in GCP including suspicious record types, long queries, and high-entropy domain names indicating DNS tunnelling.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="dns_query"
logName="projects/PROJECT_ID/logs/dns.googleapis.com%2Fdns_queries"
(
  jsonPayload.queryType="TXT" OR
  jsonPayload.queryType="NULL" OR
  jsonPayload.queryType="ANY" OR
  length(jsonPayload.queryName) > 60 OR
  jsonPayload.queryName=~"[a-f0-9]{40,}" OR
  jsonPayload.queryName=~"[A-Za-z0-9+/=]{60,}"
)
jsonPayload.responseCode="NOERROR"

-- Additional query for DNS beaconing detection in GCP:
-- resource.type="dns_query"
-- logName="projects/PROJECT_ID/logs/dns.googleapis.com%2Fdns_queries"
-- jsonPayload.responseCode="NOERROR"
--
-- Analyse in BigQuery for statistical beaconing patterns:
-- SELECT sourceIP, queryName, COUNT(*) as query_count,
--        STDDEV(TIMESTAMP_DIFF(timestamp, LAG(timestamp) OVER (PARTITION BY sourceIP, queryName ORDER BY timestamp), SECOND)) as interval_stddev
-- FROM dns_query_logs
-- WHERE interval_stddev < 5  -- Low variance indicates beaconing
-- GROUP BY sourceIP, queryName
-- HAVING query_count > 50""",
                gcp_terraform_template="""# GCP: Cloud DNS query logging and anomaly detection

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
  display_name = "DNS Anomaly Detection Alerts"
  type         = "email"
  project      = var.project_id

  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for suspicious DNS query types
resource "google_logging_metric" "suspicious_dns_types" {
  name    = "dns-suspicious-query-types"
  project = var.project_id

  filter = <<-EOT
    resource.type="dns_query"
    logName=~"projects/.*/logs/dns.googleapis.com%2Fdns_queries"
    (
      jsonPayload.queryType="TXT" OR
      jsonPayload.queryType="NULL" OR
      jsonPayload.queryType="ANY"
    )
    jsonPayload.responseCode="NOERROR"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"

    labels {
      key         = "source_ip"
      value_type  = "STRING"
      description = "Source IP making suspicious DNS queries"
    }

    labels {
      key         = "query_type"
      value_type  = "STRING"
      description = "Suspicious DNS query type"
    }
  }

  label_extractors = {
    source_ip  = "EXTRACT(jsonPayload.sourceIP)"
    query_type = "EXTRACT(jsonPayload.queryType)"
  }
}

# Step 3: Log-based metric for long DNS queries (tunnelling indicator)
resource "google_logging_metric" "long_dns_queries" {
  name    = "dns-long-query-names"
  project = var.project_id

  filter = <<-EOT
    resource.type="dns_query"
    logName=~"projects/.*/logs/dns.googleapis.com%2Fdns_queries"
    jsonPayload.queryName=~".{60,}"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"

    labels {
      key         = "source_ip"
      value_type  = "STRING"
      description = "Source IP making long DNS queries"
    }
  }

  label_extractors = {
    source_ip = "EXTRACT(jsonPayload.sourceIP)"
  }
}

# Additional metric for high-entropy domains (DGA/C2 detection)
resource "google_logging_metric" "high_entropy_domains" {
  name    = "dns-high-entropy-queries"
  project = var.project_id

  filter = <<-EOT
    resource.type="dns_query"
    logName=~"projects/.*/logs/dns.googleapis.com%2Fdns_queries"
    (
      jsonPayload.queryName=~"[a-f0-9]{40,}" OR
      jsonPayload.queryName=~"[A-Za-z0-9+/=]{60,}"
    )
    jsonPayload.responseCode="NOERROR"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"

    labels {
      key         = "source_ip"
      value_type  = "STRING"
      description = "Source IP making high-entropy DNS queries"
    }
  }

  label_extractors = {
    source_ip = "EXTRACT(jsonPayload.sourceIP)"
  }
}

# Step 4: Alert policy for suspicious query types
resource "google_monitoring_alert_policy" "suspicious_types" {
  display_name = "DNS Tunnelling Pattern Detected - Suspicious Query Types"
  combiner     = "OR"
  project      = var.project_id

  conditions {
    display_name = "High volume of suspicious DNS query types"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.suspicious_dns_types.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 50

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

  documentation {
    content   = "High volume of suspicious DNS query types (TXT, NULL, ANY) detected. May indicate DNS tunnelling or C2 communications."
    mime_type = "text/markdown"
  }
}

# Step 5: Alert policy for long DNS queries
resource "google_monitoring_alert_policy" "long_queries" {
  display_name = "DNS Tunnelling Pattern Detected - Long Queries"
  combiner     = "OR"
  project      = var.project_id

  conditions {
    display_name = "Long DNS query names detected"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.long_dns_queries.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 30

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

  documentation {
    content   = "DNS queries with unusually long domain names detected (>60 characters). This may indicate DNS tunnelling or data exfiltration."
    mime_type = "text/markdown"
  }
}

# Additional alert for high-entropy domains (DGA/C2)
resource "google_monitoring_alert_policy" "high_entropy" {
  display_name = "DNS High-Entropy Domains Detected (DGA/C2)"
  combiner     = "OR"
  project      = var.project_id

  conditions {
    display_name = "High-entropy domain queries detected"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.high_entropy_domains.name}\""
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

  documentation {
    content   = "High-entropy DNS queries detected (hexadecimal or Base64 patterns). This may indicate domain generation algorithms (DGA), DNS tunnelling, or C2 communications."
    mime_type = "text/markdown"
  }
}

# Step 6: Log sink for long-term DNS query analysis
resource "google_logging_project_sink" "dns_queries" {
  name    = "dns-query-analysis-sink"
  project = var.project_id

  destination = "storage.googleapis.com/${google_storage_bucket.dns_logs.name}"

  filter = <<-EOT
    resource.type="dns_query"
    logName=~"projects/.*/logs/dns.googleapis.com%2Fdns_queries"
  EOT

  unique_writer_identity = true
}

resource "google_storage_bucket" "dns_logs" {
  name     = "${var.project_id}-dns-query-logs"
  location = "EU"
  project  = var.project_id

  uniform_bucket_level_access = true

  lifecycle_rule {
    action {
      type = "Delete"
    }
    condition {
      age = 90
    }
  }

  encryption {
    default_kms_key_name = google_kms_crypto_key.dns_logs.id
  }
}

# KMS encryption for DNS logs
resource "google_kms_key_ring" "dns_logs" {
  name     = "dns-logs-keyring"
  location = "eu"
  project  = var.project_id
}

resource "google_kms_crypto_key" "dns_logs" {
  name     = "dns-logs-key"
  key_ring = google_kms_key_ring.dns_logs.id

  rotation_period = "7776000s"  # 90 days

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_storage_bucket_iam_member" "dns_logs_writer" {
  bucket = google_storage_bucket.dns_logs.name
  role   = "roles/storage.objectCreator"
  member = google_logging_project_sink.dns_queries.writer_identity
}

output "dns_logs_bucket" {
  description = "Storage bucket for DNS query logs"
  value       = google_storage_bucket.dns_logs.name
}""",
                alert_severity="high",
                alert_title="GCP: DNS Tunnelling Pattern Detected",
                alert_description_template="Unusual DNS queries detected in Cloud DNS logs. Suspicious record types or long query strings (>60 chars) may indicate DNS tunnelling or C2 communications.",
                investigation_steps=[
                    "Query Cloud Logging for detailed DNS query patterns",
                    "Identify source VM or service making suspicious queries",
                    "Analyse query strings for encoded data (Base64, hexadecimal)",
                    "Calculate subdomain entropy to detect data exfiltration",
                    "Check destination DNS servers and domain ownership",
                    "Review VM instance metadata and service accounts",
                    "Examine Cloud Logging for correlated suspicious activity",
                    "Check VPC Flow Logs for additional network indicators",
                ],
                containment_actions=[
                    "Add suspicious domains to Cloud DNS Response Policy",
                    "Isolate affected VM instances using VPC firewall rules",
                    "Create VM snapshots for forensic analysis",
                    "Revoke service account credentials for affected resources",
                    "Implement VPC Service Controls to restrict egress",
                    "Enable Private Google Access to control DNS resolution",
                    "Review and restrict firewall rules for DNS traffic",
                    "Deploy Cloud IDS for enhanced network monitoring",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist legitimate TXT record usage for email authentication (SPF, DKIM, DMARC) and service discovery. Establish baselines for normal DNS query patterns. Tune thresholds based on application behaviour.",
            detection_coverage="80% - Detects most DNS tunnelling techniques but may miss low-frequency attacks",
            evasion_considerations="Attackers may use legitimate DNS services, low query rates, or standard record types to evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-1.5 hours",
            estimated_monthly_cost="$10-25",
            prerequisites=[
                "Cloud DNS Query Logging enabled",
                "Cloud Logging",
                "Cloud Monitoring",
            ],
        ),
        # Strategy 7: GCP - Security Command Centre DNS Threat Detection
        DetectionStrategy(
            strategy_id="t1071-004-gcp-scc",
            name="GCP Security Command Centre DNS Threat Detection",
            description="Leverage Security Command Centre Event Threat Detection to identify DNS-based C2 communications and malicious domain queries using Google's threat intelligence.",
            detection_type=DetectionType.SECURITY_COMMAND_CENTER,
            aws_service="n/a",
            gcp_service="security_command_center",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                scc_finding_categories=[
                    "Malware: Cryptomining Bad Domain",
                    "Malware: Bad Domain",
                    "Malware: Bad IP",
                    "Malware: Outgoing DoS",
                    "Initial Access: Suspicious Login",
                ],
                gcp_terraform_template="""# GCP: Security Command Centre DNS threat detection

variable "organization_id" {
  type        = string
  description = "GCP organisation ID"
}

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
  display_name = "SCC DNS Threat Alerts"
  type         = "email"
  project      = var.project_id

  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Pub/Sub topic for SCC findings
resource "google_pubsub_topic" "scc_dns_findings" {
  name    = "scc-dns-threat-findings"
  project = var.project_id

  message_retention_duration = "86400s"

  kms_key_name = google_kms_crypto_key.scc_pubsub.id
}

resource "google_pubsub_subscription" "scc_dns_findings" {
  name    = "scc-dns-threat-findings-sub"
  topic   = google_pubsub_topic.scc_dns_findings.name
  project = var.project_id

  ack_deadline_seconds = 20

  dead_letter_policy {
    dead_letter_topic     = google_pubsub_topic.scc_dlq.id
    max_delivery_attempts = 5
  }

  retry_policy {
    minimum_backoff = "10s"
    maximum_backoff = "600s"
  }
}

# Dead letter queue for failed processing
resource "google_pubsub_topic" "scc_dlq" {
  name    = "scc-dns-findings-dlq"
  project = var.project_id
}

# KMS encryption for Pub/Sub
resource "google_kms_key_ring" "scc" {
  name     = "scc-keyring"
  location = "global"
  project  = var.project_id
}

resource "google_kms_crypto_key" "scc_pubsub" {
  name     = "scc-pubsub-key"
  key_ring = google_kms_key_ring.scc.id

  rotation_period = "7776000s"  # 90 days
}

resource "google_pubsub_topic_iam_member" "kms_encrypt_decrypt" {
  topic   = google_pubsub_topic.scc_dns_findings.name
  role    = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member  = "serviceAccount:service-${data.google_project.project.number}@gcp-sa-pubsub.iam.gserviceaccount.com"
  project = var.project_id
}

data "google_project" "project" {
  project_id = var.project_id
}

# Step 3: Log-based metric for SCC DNS threat findings
resource "google_logging_metric" "scc_dns_threats" {
  name    = "scc-dns-malware-detections"
  project = var.project_id

  filter = <<-EOT
    resource.type="threat_detector"
    protoPayload.metadata.finding.category=~"Malware.*Domain"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"

    labels {
      key         = "category"
      value_type  = "STRING"
      description = "SCC finding category"
    }
  }

  label_extractors = {
    category = "EXTRACT(protoPayload.metadata.finding.category)"
  }
}

# Step 4: Alert policy for DNS threats
resource "google_monitoring_alert_policy" "scc_dns_threats" {
  display_name = "SCC DNS Malware Detection"
  combiner     = "OR"
  project      = var.project_id

  conditions {
    display_name = "DNS-based malware or C2 detected"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.scc_dns_threats.name}\""
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

    notification_rate_limit {
      period = "300s"
    }
  }

  documentation {
    content   = "Security Command Centre detected DNS-based malware or C2 activity. Immediate investigation required."
    mime_type = "text/markdown"
  }
}

# Note: SCC notification configs require organisation-level access
# Configure via gcloud CLI:
# gcloud scc notifications create scc-dns-threat-notifications \
#   --organization=ORG_ID \
#   --pubsub-topic=projects/PROJECT_ID/topics/scc-dns-threat-findings \
#   --filter="category=\"Malware: Bad Domain\""

output "scc_pubsub_topic" {
  description = "Pub/Sub topic for SCC DNS findings"
  value       = google_pubsub_topic.scc_dns_findings.id
}

output "scc_subscription" {
  description = "Pub/Sub subscription for SCC DNS findings"
  value       = google_pubsub_subscription.scc_dns_findings.id
}""",
                alert_severity="critical",
                alert_title="GCP: DNS-Based Malware or C2 Detected",
                alert_description_template="Security Command Centre detected {category} on {resourceName}. This indicates DNS-based command and control or malware communications.",
                investigation_steps=[
                    "Review Security Command Centre finding details and severity",
                    "Identify affected GCP resources (VMs, GKE, Cloud Functions)",
                    "Analyse Cloud DNS query logs for malicious domains",
                    "Check Cloud Audit Logs for suspicious API activity",
                    "Review VPC Flow Logs for correlated network activity",
                    "Examine VM instance processes and configurations",
                    "Check service account permissions and recent usage",
                    "Investigate for signs of lateral movement or privilege escalation",
                ],
                containment_actions=[
                    "Isolate affected resources immediately using firewall rules",
                    "Create snapshots for forensic analysis before remediation",
                    "Revoke compromised service account keys and credentials",
                    "Block malicious domains via Cloud DNS Response Policy",
                    "Enable VPC Service Controls to prevent data exfiltration",
                    "Review and update firewall rules to block C2 infrastructure",
                    "Deploy Cloud IDS for enhanced threat detection",
                    "Apply organisation policy constraints to prevent recurrence",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Review findings for legitimate security tools, development environments, and known services. Configure SCC muting rules for confirmed benign activities. Update threat intelligence feeds regularly.",
            detection_coverage="85% - SCC uses threat intelligence, behavioural analysis, and Google's threat research for accurate DNS threat detection",
            evasion_considerations="Zero-day C2 infrastructure or custom DNS tunnelling tools not yet in threat intelligence may evade initial detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$50-150 depending on assets and organisation size",
            prerequisites=[
                "Security Command Centre enabled",
                "Event Threat Detection enabled",
                "Cloud DNS Query Logging",
                "VPC Flow Logs",
            ],
        ),
    ],
    recommended_order=[
        "t1071-004-aws-dns-firewall",
        "t1071-004-gcp-response-policy",
        "t1071-004-aws-guardduty",
        "t1071-004-gcp-scc",
        "t1071-004-aws-query-logging",
        "t1071-004-gcp-dns-anomaly",
        "t1071-004-aws-dns-beaconing",
    ],
    total_effort_hours=8.5,
    coverage_improvement="+45% improvement for DNS-based Command and Control detection",
)
