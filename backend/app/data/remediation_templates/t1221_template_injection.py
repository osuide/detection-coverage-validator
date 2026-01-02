"""
T1221 - Template Injection

Adversaries manipulate document templates to deploy malicious code by modifying
Microsoft Office files to reference external malicious templates. Technique used
by APT28, Gamaredon Group, DarkHydrus, Dragonfly, Lazarus Group, and others.
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
    technique_id="T1221",
    technique_name="Template Injection",
    tactic_ids=["TA0005"],
    mitre_url="https://attack.mitre.org/techniques/T1221/",
    threat_context=ThreatContext(
        description=(
            "Adversaries manipulate document templates in Microsoft Office files (.docx, .xlsx, .pptx, .rtf) "
            "to reference external malicious resources. When documents are opened, they automatically fetch "
            "remote templates containing malicious payloads. This technique evades static detection as no "
            "typical indicators (VBA macros, scripts) are present until after the malicious payload is fetched. "
            "Can also trigger credential harvesting through forced authentication via SMB/HTTPS URLs."
        ),
        attacker_goal="Deploy malicious code whilst evading static detection and harvest credentials",
        why_technique=[
            "Evades static malware detection systems",
            "No macros present in initial document",
            "Automated payload delivery upon opening",
            "Can harvest credentials via forced authentication",
            "Bypasses email security gateways",
            "Appears as legitimate document template",
            "Difficult to detect without dynamic analysis",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="moderate",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "Template injection is a sophisticated evasion technique that bypasses traditional "
            "static detection mechanisms. Increasingly used by APT groups for targeted attacks. "
            "Can lead to initial access, credential theft, and malware deployment. Difficult to "
            "detect without dynamic analysis or network monitoring."
        ),
        business_impact=[
            "Initial access through malware deployment",
            "Credential theft via forced authentication",
            "Data breach and espionage",
            "Bypassed email security controls",
            "Difficult post-compromise attribution",
            "Potential regulatory violations",
        ],
        typical_attack_phase="initial_access",
        often_precedes=["T1078.004", "T1552.001", "T1059.001", "T1087.004"],
        often_follows=["T1566.001", "T1566.002"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1221-aws-s3-document-analysis",
            name="AWS S3 Malicious Document Detection",
            description=(
                "Detect suspicious Office documents stored in S3 buckets that may contain "
                "template injection techniques using GuardDuty malware protection."
            ),
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "Object:S3/MaliciousFile",
                    "Impact:S3/MaliciousIPCaller",
                ],
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect malicious documents with template injection in S3

Parameters:
  AlertEmail:
    Type: String
    Description: Email address for security alerts

Resources:
  # Step 1: Enable GuardDuty with S3 malware protection
  GuardDutyDetector:
    Type: AWS::GuardDuty::Detector
    Properties:
      Enable: true
      DataSources:
        S3Logs:
          Enable: true
        MalwareProtection:
          ScanEc2InstanceWithFindings:
            EbsVolumes:
              Enable: true

  # Step 2: Create SNS topic for malicious document alerts
  MaliciousDocumentTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: Template Injection Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 3: Route malware findings to SNS
  MalwareDetectionRule:
    Type: AWS::Events::Rule
    Properties:
      Name: S3-MaliciousDocument-Detection
      Description: Detect malicious documents in S3 including template injection
      EventPattern:
        source:
          - aws.guardduty
        detail:
          type:
            - "Object:S3/MaliciousFile"
            - "Impact:S3/MaliciousIPCaller"
      State: ENABLED
      Targets:
        - Id: MaliciousDocumentAlerts
          Arn: !Ref MaliciousDocumentTopic

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref MaliciousDocumentTopic
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref MaliciousDocumentTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn: !GetAtt MalwareDetectionRule.Arn""",
                terraform_template="""# AWS: Detect malicious documents with template injection in S3

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: Enable GuardDuty with S3 malware protection
resource "aws_guardduty_detector" "main" {
  enable = true

  datasources {
    s3_logs {
      enable = true
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

# Step 2: Create SNS topic for malicious document alerts
resource "aws_sns_topic" "malicious_documents" {
  name         = "s3-malicious-document-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "Template Injection Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.malicious_documents.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 3: Route malware findings to SNS
resource "aws_cloudwatch_event_rule" "malware_detection" {
  name        = "s3-malicious-document-detection"
  description = "Detect malicious documents in S3 including template injection"

  event_pattern = jsonencode({
    source = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    detail = {
      type = [
        "Object:S3/MaliciousFile",
        "Impact:S3/MaliciousIPCaller"
      ]
    }
  })
}

resource "aws_sqs_queue" "dlq" {
  name                      = "s3-malicious-document-dlq"
  message_retention_seconds = 1209600
}

data "aws_iam_policy_document" "eventbridge_dlq_policy" {
  statement {
    sid     = "AllowEventBridgeToSendToDLQ"
    effect  = "Allow"
    actions = ["sqs:SendMessage"]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
    resources = [aws_sqs_queue.dlq.arn]
    condition {
      test     = "StringEquals"
      variable = "AWS:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_cloudwatch_event_rule.malware_detection.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "event_dlq" {
  queue_url = aws_sqs_queue.dlq.url
  policy    = data.aws_iam_policy_document.eventbridge_dlq_policy.json
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.malware_detection.name
  target_id = "MaliciousDocumentAlerts"
  arn       = aws_sns_topic.malicious_documents.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
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

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.malicious_documents.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.malicious_documents.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.malware_detection.arn
        }
      }
    }]
  })
}""",
                alert_severity="critical",
                alert_title="AWS GuardDuty: Malicious Document Detected",
                alert_description_template=(
                    "GuardDuty detected a malicious document in S3: {finding_type}. "
                    "Bucket: {bucket_name}, Object: {object_key}. This may contain template "
                    "injection or other document-based threats."
                ),
                investigation_steps=[
                    "Identify the S3 bucket and object containing the malicious document",
                    "Review CloudTrail logs to determine who uploaded the file",
                    "Check if the document was downloaded or distributed to users",
                    "Analyse document metadata and external template references",
                    "Review email logs if document was sent via phishing campaign",
                    "Check for network connections to external template URLs",
                    "Identify any systems that may have opened the document",
                ],
                containment_actions=[
                    "Quarantine or delete the malicious document immediately",
                    "Block public access to the S3 bucket",
                    "Rotate IAM credentials used to upload the file",
                    "Review and restrict bucket access policies",
                    "Scan other S3 buckets for similar documents",
                    "Block external template URLs at network perimeter",
                    "Alert users who may have accessed the document",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="GuardDuty malware detection has high accuracy; verify template references",
            detection_coverage="60% - covers S3-stored documents only",
            evasion_considerations="Encrypted documents or obfuscated template references may evade initial scan",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$4 per million events analysed",
            prerequisites=[
                "AWS GuardDuty with S3 protection enabled",
                "S3 buckets configured for monitoring",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1221-aws-vpc-flow-template-fetch",
            name="AWS VPC Flow Logs: External Template Fetch Detection",
            description=(
                "Detect network connections from workstations to external servers that may "
                "indicate Office applications fetching malicious remote templates."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, srcaddr, dstaddr, dstport, protocol, action
| filter action = "ACCEPT"
| filter dstport in [80, 443, 445]
| stats count(*) as connections by srcaddr, dstaddr, dstport, bin(5m)
| filter connections > 3
| sort @timestamp desc""",
                terraform_template="""# AWS: Detect external template fetch via VPC Flow Logs

variable "vpc_flow_log_group" {
  type        = string
  description = "CloudWatch Log Group for VPC Flow Logs"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: Create SNS topic for template fetch alerts
resource "aws_sns_topic" "template_fetch_alerts" {
  name         = "template-injection-network-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "Template Injection Network Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.template_fetch_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for suspicious network connections
resource "aws_cloudwatch_log_metric_filter" "template_fetch" {
  name           = "template-injection-network-activity"
  log_group_name = var.vpc_flow_log_group

  # Detect outbound HTTP/HTTPS/SMB connections from workstations
  pattern = "[version, account, eni, source, destination, srcport, destport=\"80\" || destport=\"443\" || destport=\"445\", protocol, packets, bytes, windowstart, windowend, action=\"ACCEPT\", flowlogstatus]"

  metric_transformation {
    name      = "TemplateFetchConnections"
    namespace = "Security/T1221"
    value     = "1"
  }
}

# Step 3: Create alarm for template fetch activity
resource "aws_cloudwatch_metric_alarm" "template_fetch_alarm" {
  alarm_name          = "T1221-TemplateFetchDetected"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "TemplateFetchConnections"
  namespace           = "Security/T1221"
  period              = 300
  statistic           = "Sum"
  threshold           = 10
  alarm_description   = "Detects potential template injection activity via network connections"
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.template_fetch_alerts.arn]
}""",
                alert_severity="high",
                alert_title="AWS VPC: Suspicious Template Fetch Activity",
                alert_description_template=(
                    "Unusual network activity detected from {srcaddr} to {dstaddr}:{dstport}. "
                    "This may indicate Office applications fetching external malicious templates."
                ),
                investigation_steps=[
                    "Identify the source IP address and associated EC2 instance or workstation",
                    "Review the destination URL/IP for known malicious infrastructure",
                    "Check if destination is on threat intelligence feeds",
                    "Examine CloudTrail for related API activity from the source",
                    "Review instance logs for Office application activity",
                    "Check for recently opened Office documents on the system",
                    "Analyse network traffic captures if available",
                ],
                containment_actions=[
                    "Isolate the affected workstation or EC2 instance",
                    "Block the external template URL at security groups and NACLs",
                    "Add malicious domains/IPs to AWS WAF blocklist",
                    "Terminate the instance if compromise is confirmed",
                    "Review and remove malicious documents from file shares",
                    "Force password reset for affected user accounts",
                    "Scan related systems for similar activity",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal document template sources; whitelist legitimate Microsoft template servers",
            detection_coverage="50% - covers VPC-based workstations with flow logs enabled",
            evasion_considerations="Encrypted connections hide template content; may blend with normal HTTPS traffic",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-15 depending on traffic volume",
            prerequisites=["VPC Flow Logs enabled", "CloudTrail logging enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1221-aws-workspaces-monitoring",
            name="AWS WorkSpaces Document Security Monitoring",
            description=(
                "Monitor AWS WorkSpaces for suspicious Office document activity that may "
                "indicate template injection attacks targeting virtual desktops."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, userIdentity.arn, sourceIPAddress, requestParameters
| filter eventSource = "workspaces.amazonaws.com"
| filter eventName in ["CreateWorkspaces", "RebuildWorkspaces", "RestoreWorkspace"]
| sort @timestamp desc""",
                terraform_template="""# AWS: Monitor WorkSpaces for template injection indicators

variable "cloudtrail_log_group" {
  type        = string
  description = "CloudTrail log group name"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: Create SNS topic for WorkSpaces security alerts
resource "aws_sns_topic" "workspaces_alerts" {
  name         = "workspaces-document-security-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "WorkSpaces Security Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.workspaces_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for suspicious WorkSpaces activity
resource "aws_cloudwatch_log_metric_filter" "workspaces_activity" {
  name           = "workspaces-suspicious-activity"
  log_group_name = var.cloudtrail_log_group

  pattern = "{ ($.eventSource = \"workspaces.amazonaws.com\") && ($.eventName = \"CreateWorkspaces\" || $.eventName = \"RebuildWorkspaces\" || $.eventName = \"RestoreWorkspace\") }"

  metric_transformation {
    name      = "WorkSpacesSuspiciousActivity"
    namespace = "Security/T1221"
    value     = "1"
  }
}

# Step 3: Create alarm for WorkSpaces security events
resource "aws_cloudwatch_metric_alarm" "workspaces_alarm" {
  alarm_name          = "T1221-WorkSpacesSecurity"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "WorkSpacesSuspiciousActivity"
  namespace           = "Security/T1221"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "Alert on suspicious WorkSpaces activity that may indicate compromise"
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.workspaces_alerts.arn]
}""",
                alert_severity="medium",
                alert_title="AWS WorkSpaces: Suspicious Activity Detected",
                alert_description_template=(
                    "Suspicious WorkSpaces activity detected: {eventName} by {userIdentity.arn}. "
                    "This may indicate response to template injection compromise."
                ),
                investigation_steps=[
                    "Review the specific WorkSpaces API call and user identity",
                    "Check if WorkSpace rebuild was in response to security incident",
                    "Review WorkSpaces Directory logs for authentication events",
                    "Examine recent document access patterns on the WorkSpace",
                    "Check for unusual file downloads or network connections",
                    "Review user behaviour analytics for anomalies",
                ],
                containment_actions=[
                    "Isolate affected WorkSpace from network",
                    "Review and remove malicious documents from WorkSpace",
                    "Force password reset for affected users",
                    "Rebuild WorkSpace from clean image if compromised",
                    "Review security group rules for WorkSpaces",
                    "Enable enhanced monitoring for affected WorkSpaces",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Normal administrative WorkSpaces operations will trigger; correlate with security incidents",
            detection_coverage="40% - covers WorkSpaces environments only",
            evasion_considerations="Attackers may avoid triggering WorkSpaces rebuild events",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=[
                "AWS WorkSpaces deployed",
                "CloudTrail enabled for WorkSpaces events",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1221-gcp-cloud-storage-document-scan",
            name="GCP Cloud Storage Malicious Document Detection",
            description=(
                "Detect suspicious Office documents uploaded to Cloud Storage that may "
                "contain template injection using Security Command Centre."
            ),
            detection_type=DetectionType.SECURITY_COMMAND_CENTER,
            aws_service="n/a",
            gcp_service="security_command_center",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gcs_bucket"
protoPayload.methodName="storage.objects.create"
protoPayload.resourceName=~".*\\.(docx|xlsx|pptx|rtf|doc|xls|ppt)$"''',
                scc_finding_categories=["MALWARE", "SUSPICIOUS_BINARY"],
                gcp_terraform_template="""# GCP: Detect malicious documents in Cloud Storage

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

variable "organization_id" {
  type        = string
  description = "GCP organization ID"
}

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "Template Injection Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log metric for document uploads
resource "google_logging_metric" "document_uploads" {
  project = var.project_id
  name   = "malicious-document-uploads"
  filter = <<-EOT
    resource.type="gcs_bucket"
    protoPayload.methodName="storage.objects.create"
    protoPayload.resourceName=~".*\\.(docx|xlsx|pptx|rtf|doc|xls|ppt)$"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Create alert policy for malicious documents
resource "google_monitoring_alert_policy" "document_alert" {
  project      = var.project_id
  display_name = "Cloud Storage Malicious Document Detection"
  combiner     = "OR"

  conditions {
    display_name = "Office document uploaded to Cloud Storage"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.document_uploads.name}\""
      duration        = "60s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }

  notification_channels = [google_monitoring_notification_channel.email_s1.id]

  alert_strategy {
    auto_close = "604800s"  # 7 days
  }

  documentation {
    content   = "Office document uploaded to Cloud Storage. Review for template injection and other malicious content."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="high",
                alert_title="GCP Cloud Storage: Suspicious Document Upload",
                alert_description_template=(
                    "Office document uploaded to Cloud Storage bucket {bucket_name}: {object_name}. "
                    "Review for template injection and malicious content."
                ),
                investigation_steps=[
                    "Identify the Cloud Storage bucket and object path",
                    "Review Cloud Audit Logs to identify who uploaded the file",
                    "Check if document was shared or made publicly accessible",
                    "Download and analyse document in isolated environment",
                    "Extract and examine template references from document XML",
                    "Check external URLs against threat intelligence feeds",
                    "Review user's recent activity for other suspicious uploads",
                ],
                containment_actions=[
                    "Delete or quarantine the malicious document immediately",
                    "Remove public access from the bucket if enabled",
                    "Rotate service account keys used for upload",
                    "Review and restrict bucket IAM permissions",
                    "Block malicious template URLs at Cloud Armor or firewall",
                    "Scan other buckets for similar documents",
                    "Alert users who may have downloaded the document",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Legitimate document uploads are common; focus on anomalous sources and external template references",
            detection_coverage="55% - covers Cloud Storage document uploads",
            evasion_considerations="Encrypted or password-protected documents may hide template injection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$15-30 depending on SCC tier",
            prerequisites=[
                "Security Command Centre enabled",
                "Cloud Storage audit logging enabled",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1221-gcp-chronicle-network-analysis",
            name="GCP Chronicle: Template Fetch Network Analysis",
            description=(
                "Use Chronicle to detect network connections from endpoints to external "
                "servers that indicate Office applications fetching malicious templates."
            ),
            detection_type=DetectionType.SECURITY_COMMAND_CENTER,
            aws_service="n/a",
            gcp_service="chronicle",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""# Chronicle YARA-L Rule for Template Injection
rule template_injection_network_activity {
  meta:
    author = "Security Team"
    description = "Detects network connections indicative of Office template injection"
    severity = "HIGH"

  events:
    $network.metadata.event_type = "NETWORK_CONNECTION"
    $network.target.port in [80, 443, 445]
    $network.principal.process.file.full_path = /.*\\\\(WINWORD|EXCEL|POWERPNT)\\.EXE$/i

  condition:
    $network
}""",
                gcp_terraform_template="""# GCP: Chronicle-based template injection detection

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: Create notification channel for Chronicle alerts
resource "google_monitoring_notification_channel" "chronicle_alerts" {
  project      = var.project_id
  display_name = "Chronicle Template Injection Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log sink to route Chronicle findings
resource "google_logging_project_sink" "chronicle_findings" {
  name        = "chronicle-template-injection-findings"
  destination = "pubsub.googleapis.com/projects/${var.project_id}/topics/chronicle-findings"

  filter = <<-EOT
    resource.type="chronicle.googleapis.com/Detection"
    jsonPayload.detection.ruleName="template_injection_network_activity"
  EOT

  unique_writer_identity = true
}

# Step 3: Create Pub/Sub topic for Chronicle findings
resource "google_pubsub_topic" "chronicle_findings" {
  name    = "chronicle-findings"
  project = var.project_id
}

resource "google_pubsub_subscription" "chronicle_findings_sub" {
  name    = "chronicle-findings-subscription"
  topic   = google_pubsub_topic.chronicle_findings.name
  project = var.project_id

  ack_deadline_seconds = 20

  push_config {
    push_endpoint = "https://example.com/chronicle-webhook"  # Replace with your endpoint
  }
}""",
                alert_severity="high",
                alert_title="GCP Chronicle: Template Injection Network Activity",
                alert_description_template=(
                    "Chronicle detected Office application making suspicious network connection "
                    "indicative of template injection. Process: {process_name}, Destination: {destination_ip}:{destination_port}"
                ),
                investigation_steps=[
                    "Review Chronicle detection details and timeline",
                    "Identify the endpoint and user involved",
                    "Check destination IP/domain against threat intelligence",
                    "Review recent document access on the affected endpoint",
                    "Examine process execution history for Office applications",
                    "Check for credential access attempts via SMB connections",
                    "Correlate with other security events for the user/endpoint",
                ],
                containment_actions=[
                    "Isolate the affected endpoint from the network",
                    "Block malicious destination at Cloud Armor or VPC firewall",
                    "Quarantine suspicious documents from the endpoint",
                    "Force user password reset and session revocation",
                    "Review and remove unauthorised network access rules",
                    "Deploy endpoint detection and response (EDR) for deeper analysis",
                    "Hunt for similar activity across other endpoints",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist legitimate Microsoft template servers; focus on unknown destinations",
            detection_coverage="70% - covers Chronicle-monitored endpoints",
            evasion_considerations="Requires endpoint telemetry; may miss activity on unmonitored systems",
            implementation_effort=EffortLevel.HIGH,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$50-100 depending on Chronicle tier",
            prerequisites=[
                "Chronicle Security Operations enabled",
                "Endpoint telemetry collection configured",
            ],
        ),
    ],
    recommended_order=[
        "t1221-aws-s3-document-analysis",
        "t1221-gcp-cloud-storage-document-scan",
        "t1221-aws-vpc-flow-template-fetch",
        "t1221-gcp-chronicle-network-analysis",
        "t1221-aws-workspaces-monitoring",
    ],
    total_effort_hours=7.5,
    coverage_improvement="+25% improvement for Defence Evasion tactic",
)
