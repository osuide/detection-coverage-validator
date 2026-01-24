"""
T1189 - Drive-by Compromise

Adversaries gain access when users visit websites during normal browsing.
Exploits client-side vulnerabilities through compromised sites, malvertising, and watering holes.
Used by APT28, APT29, APT32, APT37, APT38, Lazarus Group, Dragonfly, Turla.
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
    technique_id="T1189",
    technique_name="Drive-by Compromise",
    tactic_ids=["TA0001"],
    mitre_url="https://attack.mitre.org/techniques/T1189/",
    threat_context=ThreatContext(
        description=(
            "Adversaries gain system access when users visit websites during normal browsing. "
            "The technique exploits vulnerable client-side software (browsers, plugins) rather "
            "than targeting external-facing applications. Common delivery methods include "
            "compromised legitimate websites, malvertising campaigns, and strategic web compromises "
            "(watering hole attacks) targeting specific communities or industries."
        ),
        attacker_goal="Gain initial access by exploiting client-side vulnerabilities during web browsing",
        why_technique=[
            "Targets users directly through normal browsing behaviour",
            "Bypasses perimeter security controls",
            "Watering holes target specific victim organisations",
            "Leverages trusted websites to deliver payloads",
            "Exploits unpatched browsers and plugins",
            "Difficult for users to identify malicious sites",
            "Malvertising reaches wide audiences via legitimate ad networks",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="moderate",
        trend="stable",
        severity_score=8,
        severity_reasoning=(
            "Highly effective initial access technique that exploits user trust in legitimate websites. "
            "Strategic web compromises (watering holes) enable targeted attacks against specific "
            "organisations or industries. Difficult to detect as user browsing appears normal. "
            "Can bypass traditional perimeter defences and reach internal networks."
        ),
        business_impact=[
            "Initial endpoint compromise within corporate network",
            "Malware installation on user workstations",
            "Credential theft from compromised endpoints",
            "Lateral movement enabler from initial foothold",
            "Data exfiltration from infected systems",
            "Bypass of perimeter security controls",
        ],
        typical_attack_phase="initial_access",
        often_precedes=["T1078.004", "T1059", "T1105", "T1003"],
        often_follows=["T1566", "T1598"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1189-aws-guardduty-dns",
            name="AWS GuardDuty Malicious Domain Detection",
            description=(
                "Detect endpoint connections to known malicious domains associated with "
                "drive-by compromise campaigns, including C2 infrastructure and exploit kits."
            ),
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "Backdoor:EC2/C&CActivity.B!DNS",
                    "CryptoCurrency:EC2/BitcoinTool.B!DNS",
                    "Trojan:EC2/BlackholeTraffic",
                    "Trojan:EC2/DropPoint",
                    "UnauthorizedAccess:EC2/MaliciousIPCaller.Custom",
                    "Trojan:EC2/DriveBySourceTraffic!DNS",
                ],
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: GuardDuty monitoring for drive-by compromise indicators (T1189)

Parameters:
  AlertEmail:
    Type: String
    Description: Email address for security alerts

Resources:
  # Step 1: Create SNS topic for GuardDuty alerts
  GuardDutyAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      TopicName: t1189-guardduty-alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: EventBridge rule to capture GuardDuty findings
  GuardDutyEventRule:
    Type: AWS::Events::Rule
    Properties:
      Name: t1189-guardduty-malicious-domains
      Description: Detect malicious domain connections
      State: ENABLED
      EventPattern:
        source:
          - aws.guardduty
        detail-type:
          - GuardDuty Finding
        detail:
          type:
            - prefix: "Backdoor:EC2/"
            - prefix: "Trojan:EC2/"
            - prefix: "UnauthorizedAccess:EC2/MaliciousIPCaller.Custom"
      Targets:
        - Arn: !Ref GuardDutyAlertTopic
          Id: GuardDutySNSTarget

  # Step 3: Allow EventBridge to publish to SNS
  SNSTopicPolicy:
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
            Resource: !Ref GuardDutyAlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn: !GetAtt GuardDutyEventRule.Arn""",
                terraform_template="""# AWS: GuardDuty monitoring for drive-by compromise (T1189)

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: Create SNS topic for GuardDuty alerts
resource "aws_sns_topic" "guardduty_alerts" {
  name = "t1189-guardduty-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.guardduty_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule to capture GuardDuty findings
resource "aws_cloudwatch_event_rule" "guardduty_malicious" {
  name        = "t1189-guardduty-malicious-domains"
  description = "Detect malicious domain connections from drive-by compromise"
  state       = "ENABLED"
  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [
        { prefix = "Backdoor:EC2/" },
        { prefix = "Trojan:EC2/" },
        { prefix = "UnauthorizedAccess:EC2/MaliciousIPCaller.Custom" }
      ]
    }
  })
}

# Step 3: Route GuardDuty findings to SNS
resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.guardduty_malicious.name
  target_id = "GuardDutySNSTarget"
  arn       = aws_sns_topic.guardduty_alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.guardduty_driveby_dlq.arn
  }
  input_transformer {
    input_paths = {
      account    = "$.account"
      region     = "$.region"
      time       = "$.time"
      type       = "$.detail.type"
      severity   = "$.detail.severity"
      title      = "$.detail.title"
      description = "$.detail.description"
    }

    input_template = <<-EOT
"GuardDuty Finding Alert
Time: <time>
Account: <account>
Region: <region>
Finding: <type>
Severity: <severity>
Title: <title>
Description: <description>
Action: Review finding in GuardDuty console and investigate"
EOT
  }

}

resource "aws_sqs_queue" "guardduty_driveby_dlq" {
  name                      = "guardduty-driveby-alerts-dlq"
  message_retention_seconds = 1209600
}

resource "aws_sqs_queue_policy" "guardduty_driveby_dlq_policy" {
  queue_url = aws_sqs_queue.guardduty_driveby_dlq.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.guardduty_driveby_dlq.arn
      Condition = {
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.guardduty_malicious.arn
        }
      }
    }]
  })
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.guardduty_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.guardduty_alerts.arn
    Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
          ArnEquals = {
            "aws:SourceArn" = aws_cloudwatch_event_rule.guardduty_malicious.arn
          }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="Drive-by Compromise: Malicious Domain Connection",
                alert_description_template=(
                    "Instance {resource.instanceDetails.instanceId} connected to known malicious domain. "
                    "Finding type: {type}. Severity: {severity}."
                ),
                investigation_steps=[
                    "Identify the affected EC2 instance and its role",
                    "Review CloudTrail logs for user activity on the instance",
                    "Check instance web browsing history and DNS queries",
                    "Review running processes and network connections",
                    "Examine VPC Flow Logs for suspicious traffic patterns",
                    "Check for unauthorised software installations",
                    "Review IAM credentials accessed from the instance",
                    "Identify whether instance has internet gateway access",
                ],
                containment_actions=[
                    "Isolate the affected instance in a quarantine security group",
                    "Block the malicious domain at network firewall/DNS level",
                    "Terminate the instance if compromise is confirmed",
                    "Rotate all IAM credentials accessed from the instance",
                    "Review and revoke any temporary credentials issued",
                    "Create forensic snapshot before termination",
                    "Update security group rules to restrict outbound access",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="GuardDuty uses threat intelligence feeds; false positives are rare",
            detection_coverage="75% - detects known malicious domains and C2 infrastructure",
            evasion_considerations="New/unknown malicious domains not in threat feeds will be missed",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$15-50 depending on instance count",
            prerequisites=["GuardDuty enabled in region", "VPC DNS logging enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1189-aws-cloudwatch-browser",
            name="AWS CloudWatch Suspicious Browser Process Detection",
            description=(
                "Monitor for suspicious child processes spawned from browser applications, "
                "indicating successful exploitation from drive-by compromise."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, process.name, process.parent, commandLine, sourceIPAddress
| filter process.parent like /chrome|firefox|safari|msedge|iexplore/
| filter process.name in ["powershell", "cmd", "bash", "sh", "python", "perl", "ruby", "wscript", "cscript"]
| stats count(*) as spawn_count,
        count_distinct(process.name) as unique_processes
  by process.parent, sourceIPAddress, bin(1h)
| filter spawn_count > 3 or unique_processes > 2
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect suspicious browser child processes (T1189)

Parameters:
  LogGroupName:
    Type: String
    Description: CloudWatch log group for endpoint logs
  AlertEmail:
    Type: String

Resources:
  # Step 1: Create SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      TopicName: t1189-browser-exploit-alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter for suspicious browser processes
  BrowserExploitFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref LogGroupName
      FilterPattern: '[process_parent=*chrome* || process_parent=*firefox* || process_parent=*safari*, process_name=powershell || process_name=cmd || process_name=bash]'
      MetricTransformations:
        - MetricName: SuspiciousBrowserProcess
          MetricNamespace: Security/T1189
          MetricValue: "1"

  # Step 3: Alarm on suspicious activity
  BrowserExploitAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1189-BrowserExploitation
      AlarmDescription: Suspicious child process from browser detected
      MetricName: SuspiciousBrowserProcess
      Namespace: Security/T1189
      Statistic: Sum
      Period: 300
      Threshold: 5
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref AlertTopic

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref AlertTopic]
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: cloudwatch.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic""",
                terraform_template="""# AWS: Detect suspicious browser child processes (T1189)

variable "log_group_name" {
  type        = string
  description = "CloudWatch log group for endpoint logs"
}

variable "alert_email" {
  type = string
}

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "browser_alerts" {
  name = "t1189-browser-exploit-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.browser_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for suspicious browser processes
resource "aws_cloudwatch_log_metric_filter" "browser_exploit" {
  name           = "suspicious-browser-processes"
  log_group_name = var.log_group_name
  pattern        = "[process_parent=*chrome* || process_parent=*firefox* || process_parent=*safari*, process_name=powershell || process_name=cmd || process_name=bash]"

  metric_transformation {
    name      = "SuspiciousBrowserProcess"
    namespace = "Security/T1189"
    value     = "1"
  }
}

# Step 3: Alarm on suspicious browser activity
resource "aws_cloudwatch_metric_alarm" "browser_exploitation" {
  alarm_name          = "T1189-BrowserExploitation"
  alarm_description   = "Suspicious child process spawned from browser"
  metric_name         = "SuspiciousBrowserProcess"
  namespace           = "Security/T1189"
  statistic           = "Sum"
  period              = 300
  threshold           = 5
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.browser_alerts.arn]
}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.browser_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.browser_alerts.arn
    Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}""",
                alert_severity="critical",
                alert_title="Drive-by Compromise: Browser Exploitation Detected",
                alert_description_template=(
                    "Suspicious processes spawned from browser {process.parent}. "
                    "{spawn_count} processes detected including {process.name}."
                ),
                investigation_steps=[
                    "Identify which user account was browsing",
                    "Review browser history and recently visited URLs",
                    "Examine spawned process command lines and arguments",
                    "Check for downloaded files in browser cache/downloads",
                    "Review DNS queries immediately before process spawn",
                    "Analyse memory dumps of browser process if available",
                    "Check for persistence mechanisms created",
                    "Review network connections from spawned processes",
                ],
                containment_actions=[
                    "Isolate the affected workstation immediately",
                    "Kill suspicious processes and child processes",
                    "Block identified malicious domains at DNS/firewall",
                    "Scan the endpoint with updated antivirus",
                    "Remove browser cache and temporary files",
                    "Rotate user credentials accessed from the endpoint",
                    "Re-image the workstation if compromise confirmed",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist legitimate browser extensions and automation tools",
            detection_coverage="65% - detects post-exploitation process activity",
            evasion_considerations="Fileless attacks or in-memory exploitation may evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-25",
            prerequisites=[
                "Endpoint logging to CloudWatch",
                "Process creation logging enabled",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1189-aws-waf-malvertising",
            name="AWS WAF Malicious JavaScript Detection",
            description=(
                "Detect injection of malicious JavaScript or iFrames into web responses, "
                "indicating compromised web infrastructure serving drive-by exploits."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, request.uri, response.status, request.headers.referer
| filter request.uri like /\\.js$|<iframe|<script/
| filter response.headers.content_type like /javascript|html/
| filter request.uri like /eval\\(|document\\.write|window\\.location|atob\\(/
| stats count(*) as suspicious_js by request.uri, bin(5m)
| filter suspicious_js > 10
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect malicious JavaScript in web responses (T1189)

Parameters:
  ALBLogGroup:
    Type: String
    Description: ALB or web server log group
  AlertEmail:
    Type: String

Resources:
  # Step 1: Create SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      TopicName: t1189-malvertising-alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter for suspicious JavaScript
  MaliciousJSFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref ALBLogGroup
      FilterPattern: '[request_uri=*.js* || request_uri=*<iframe* || request_uri=*<script*, response=*eval* || response=*atob* || response=*document.write*]'
      MetricTransformations:
        - MetricName: MaliciousJavaScript
          MetricNamespace: Security/T1189
          MetricValue: "1"

  # Step 3: Alert on suspicious JavaScript patterns
  MalvertisiingAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1189-MaliciousJavaScript
      AlarmDescription: Suspicious JavaScript patterns in web responses
      MetricName: MaliciousJavaScript
      Namespace: Security/T1189
      Statistic: Sum
      Period: 300
      Threshold: 20
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref AlertTopic

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref AlertTopic]
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: cloudwatch.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic""",
                terraform_template="""# AWS: Detect malicious JavaScript serving (T1189)

variable "alb_log_group" {
  type        = string
  description = "ALB access log group"
}

variable "alert_email" {
  type = string
}

# Step 1: Create SNS topic
resource "aws_sns_topic" "malvertising_alerts" {
  name = "t1189-malvertising-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.malvertising_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for suspicious JavaScript
resource "aws_cloudwatch_log_metric_filter" "malicious_js" {
  name           = "malicious-javascript-serving"
  log_group_name = var.alb_log_group
  pattern        = "[request_uri=*.js* || request_uri=*<iframe* || request_uri=*<script*, response=*eval* || response=*atob* || response=*document.write*]"

  metric_transformation {
    name      = "MaliciousJavaScript"
    namespace = "Security/T1189"
    value     = "1"
  }
}

# Step 3: Alert on suspicious JavaScript delivery
resource "aws_cloudwatch_metric_alarm" "malvertising" {
  alarm_name          = "T1189-MaliciousJavaScript"
  alarm_description   = "Suspicious JavaScript patterns detected in web responses"
  metric_name         = "MaliciousJavaScript"
  namespace           = "Security/T1189"
  statistic           = "Sum"
  period              = 300
  threshold           = 20
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.malvertising_alerts.arn]
}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.malvertising_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.malvertising_alerts.arn
    Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="Drive-by Compromise: Malicious JavaScript Detected",
                alert_description_template=(
                    "Suspicious JavaScript patterns detected in {request.uri}. "
                    "{suspicious_js} requests in 5 minutes."
                ),
                investigation_steps=[
                    "Identify the origin of the suspicious JavaScript files",
                    "Compare current files with known-good versions",
                    "Check for unauthorised modifications to web application",
                    "Review CloudTrail for recent S3 or deployment changes",
                    "Scan web server for compromise indicators",
                    "Check for SQL injection or other web vulnerabilities",
                    "Review CDN/CloudFront cache for poisoned content",
                    "Identify visitor IPs that received malicious content",
                ],
                containment_actions=[
                    "Remove malicious JavaScript files immediately",
                    "Invalidate CloudFront cache if CDN is compromised",
                    "Block write access to web content directories",
                    "Deploy known-good version from version control",
                    "Enable CloudFront signed URLs if not already enabled",
                    "Review and patch web application vulnerabilities",
                    "Notify affected users if visitor data compromised",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline legitimate JavaScript patterns and obfuscation techniques",
            detection_coverage="60% - pattern-based detection of exploit JavaScript",
            evasion_considerations="Advanced obfuscation and polymorphic code may evade signatures",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$8-20",
            prerequisites=[
                "ALB or CloudFront logging enabled",
                "Web application logs forwarded to CloudWatch",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1189-gcp-dns-threat-intel",
            name="GCP Cloud DNS Threat Intelligence",
            description=(
                "Monitor Cloud DNS queries for domains associated with exploit kits, "
                "malvertising networks, and known drive-by compromise infrastructure."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="dns_query"
(jsonPayload.queryName=~".*\\.tk$|.*\\.ml$|.*\\.ga$|.*\\.cf$"
OR jsonPayload.responseCode="NOERROR"
   jsonPayload.queryName=~".*exploit.*|.*malware.*|.*payload.*")
severity>="WARNING"''',
                gcp_terraform_template="""# GCP: Monitor DNS queries for drive-by compromise indicators (T1189)

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type = string
}

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "T1189 DNS Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log metric for suspicious DNS queries
resource "google_logging_metric" "suspicious_dns" {
  project = var.project_id
  name   = "t1189-suspicious-dns-queries"
  filter = <<-EOT
    resource.type="dns_query"
    (jsonPayload.queryName=~".*\\.tk$|.*\\.ml$|.*\\.ga$|.*\\.cf$"
    OR jsonPayload.queryName=~".*exploit.*|.*malware.*|.*payload.*")
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "query_name"
      value_type  = "STRING"
      description = "DNS query domain"
    }
  }
  label_extractors = {
    "query_name" = "EXTRACT(jsonPayload.queryName)"
  }
}

# Step 3: Create alert policy for malicious DNS activity
resource "google_monitoring_alert_policy" "dns_threats" {
  project      = var.project_id
  display_name = "T1189: Drive-by Compromise DNS Indicators"
  combiner     = "OR"
  conditions {
    display_name = "Suspicious DNS queries detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.suspicious_dns.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 10
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }
  notification_channels = [google_monitoring_notification_channel.email_s1.id]
  alert_strategy {
    auto_close = "86400s"  # 24 hours
  }
}""",
                alert_severity="high",
                alert_title="GCP: Drive-by Compromise DNS Activity",
                alert_description_template=(
                    "Suspicious DNS queries detected for domain {query_name}. "
                    "Potential drive-by compromise or malware communication."
                ),
                investigation_steps=[
                    "Identify which VM instances made the DNS queries",
                    "Review VPC Flow Logs for connections to resolved IPs",
                    "Check Cloud Logging for user activity on affected instances",
                    "Examine running processes on querying instances",
                    "Review browser history if queries from user workstations",
                    "Check for correlation with threat intelligence feeds",
                    "Identify applications making the DNS requests",
                ],
                containment_actions=[
                    "Block the malicious domains using Cloud DNS policies",
                    "Isolate affected VM instances in separate VPC",
                    "Deploy firewall rules to block outbound connections",
                    "Scan instances with Cloud Security Scanner",
                    "Rotate service account credentials from affected VMs",
                    "Review and remove any malware or backdoors",
                    "Re-create instances from known-good images",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Filter legitimate use of free TLDs and tune domain patterns",
            detection_coverage="70% - detects known malicious domain patterns",
            evasion_considerations="DGA domains and fast-flux networks may evade pattern detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="45 minutes - 1 hour",
            estimated_monthly_cost="$12-25",
            prerequisites=["Cloud DNS logging enabled", "VPC Flow Logs enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1189-gcp-chrome-policy",
            name="GCP Chrome Enterprise Browser Policy Violations",
            description=(
                "Monitor Chrome Enterprise browser policy violations indicating exploitation "
                "attempts or suspicious browser behaviour from drive-by attacks."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="chrome_policy"
(protoPayload.metadata.event.eventType="CHROME_POLICY_VIOLATION"
OR protoPayload.metadata.event.eventType="EXTENSION_INSTALL_BLOCKED"
OR protoPayload.metadata.event.eventType="DOWNLOAD_BLOCKED")
severity="ERROR"''',
                gcp_terraform_template="""# GCP: Monitor Chrome browser policy violations (T1189)

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type = string
}

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "email_s2" {
  project      = var.project_id
  display_name = "Chrome Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log metric for browser policy violations
resource "google_logging_metric" "browser_violations" {
  project = var.project_id
  name   = "t1189-chrome-policy-violations"
  filter = <<-EOT
    resource.type="chrome_policy"
    (protoPayload.metadata.event.eventType="CHROME_POLICY_VIOLATION"
    OR protoPayload.metadata.event.eventType="EXTENSION_INSTALL_BLOCKED"
    OR protoPayload.metadata.event.eventType="DOWNLOAD_BLOCKED")
    severity="ERROR"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert on suspicious browser activity
resource "google_monitoring_alert_policy" "browser_exploitation" {
  project      = var.project_id
  display_name = "T1189: Browser Policy Violations"
  combiner     = "OR"
  conditions {
    display_name = "High rate of policy violations"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.browser_violations.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 5
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_RATE"
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
}""",
                alert_severity="medium",
                alert_title="GCP: Browser Policy Violation - Potential Drive-by Attack",
                alert_description_template=(
                    "Chrome Enterprise policy violation: {eventType} for user {principalEmail}. "
                    "Potential drive-by compromise attempt blocked."
                ),
                investigation_steps=[
                    "Identify the user experiencing policy violations",
                    "Review which websites triggered the violations",
                    "Check browser extension install attempts",
                    "Examine blocked download file types and sources",
                    "Review recent browsing history for the user",
                    "Check for multiple violations in short timeframe",
                    "Verify Chrome Enterprise policies are correctly configured",
                ],
                containment_actions=[
                    "Contact user to verify browsing activity was legitimate",
                    "Block identified malicious URLs in Chrome policies",
                    "Strengthen browser security policies if needed",
                    "Review and update extension whitelists",
                    "Enable additional Chrome Enterprise security features",
                    "Provide security awareness training to affected users",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Distinguish between policy violations from malware vs user behaviour",
            detection_coverage="55% - requires Chrome Enterprise deployment",
            evasion_considerations="Only effective for Chrome browser; other browsers not covered",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-12",
            prerequisites=["Chrome Enterprise Browser Cloud Management enabled"],
        ),
        # Azure Strategy: Drive-by Compromise
        DetectionStrategy(
            strategy_id="t1189-azure",
            name="Azure Drive-by Compromise Detection",
            description=(
                "Azure detection for Drive-by Compromise. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.DEFENDER_ALERT,
            aws_service="n/a",
            azure_service="defender",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                defender_alert_types=["Suspicious activity detected"],
                azure_terraform_template="""# Microsoft Defender for Cloud Detection
# Drive-by Compromise (T1189)
# Microsoft Defender detects Drive-by Compromise activity

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
  name                = "defender-t1189-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "DefAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Log Analytics query for Defender alerts
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "defender_detection" {
  name                = "defender-t1189"
  resource_group_name = var.resource_group_name
  location            = "uksouth"

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
                    "Suspicious activity detected",
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

  description = "Microsoft Defender detects Drive-by Compromise activity"
  display_name = "Defender: Drive-by Compromise"
  enabled      = true

  tags = {
    "mitre-technique" = "T1189"
    "detection-type"  = "security"
  }
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.defender_detection.id
}""",
                alert_severity="high",
                alert_title="Azure: Drive-by Compromise Detected",
                alert_description_template=(
                    "Drive-by Compromise activity detected. "
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
        "t1189-aws-guardduty-dns",
        "t1189-gcp-dns-threat-intel",
        "t1189-aws-cloudwatch-browser",
        "t1189-aws-waf-malvertising",
        "t1189-gcp-chrome-policy",
    ],
    total_effort_hours=5.5,
    coverage_improvement="+18% improvement for Initial Access tactic",
)
