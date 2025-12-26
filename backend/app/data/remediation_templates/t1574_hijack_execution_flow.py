"""
T1574 - Hijack Execution Flow

Adversaries may execute their own malicious payloads by hijacking the way operating systems
run programs. Common methods include DLL hijacking, dylib hijacking, path interception, and
manipulating search order hijacking.
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
    technique_id="T1574",
    technique_name="Hijack Execution Flow",
    tactic_ids=["TA0003", "TA0004", "TA0005"],
    mitre_url="https://attack.mitre.org/techniques/T1574/",
    threat_context=ThreatContext(
        description=(
            "Adversaries execute malicious payloads by intercepting how operating systems "
            "run programs. This includes manipulating library loading paths, file directories, "
            "and registry locations to redirect execution flow. In cloud environments, this "
            "manifests through container image manipulation, instance userdata modification, "
            "and runtime configuration hijacking."
        ),
        attacker_goal="Execute malicious code by hijacking normal program execution flow",
        why_technique=[
            "Achieves persistence without creating new processes",
            "Difficult to detect as it mimics legitimate program behaviour",
            "Can escalate privileges by hijacking privileged processes",
            "Evades detection by not creating suspicious files",
            "Survives reboots and system updates",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "Execution flow hijacking is highly effective for persistence and privilege escalation. "
            "It's particularly dangerous because it's difficult to detect and can affect multiple "
            "processes simultaneously. In cloud environments, compromised images or instances "
            "can spread hijacked execution flows across entire deployments."
        ),
        business_impact=[
            "Persistent unauthorised access to systems",
            "Privilege escalation to root or administrator",
            "Compromise of multiple systems through shared images",
            "Data theft through compromised application execution",
            "Supply chain compromise affecting customers",
        ],
        typical_attack_phase="persistence",
        often_precedes=["T1003", "T1068", "T1082"],
        often_follows=["T1078", "T1190", "T1610"],
    ),
    detection_strategies=[
        # Strategy 1: AWS - Container Image Modifications
        DetectionStrategy(
            strategy_id="t1574-aws-ecr-image-scan",
            name="ECR Image Vulnerability and Malware Scanning",
            description=(
                "AWS ECR image scanning detects vulnerabilities and malware in container images "
                "that could be used for execution flow hijacking, including suspicious libraries "
                "and binaries."
            ),
            detection_type=DetectionType.GUARDDUTY,
            aws_service="ecr",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "Execution:Runtime/MaliciousFileExecuted",
                    "Execution:Container/SuspiciousFile",
                ],
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: ECR image scanning with GuardDuty for execution hijacking detection

Parameters:
  AlertEmail:
    Type: String

Resources:
  # Step 1: Enable ECR scanning configuration
  ECRScanningConfig:
    Type: AWS::ECR::RegistryPolicy
    Properties:
      PolicyText:
        Version: '2012-10-17'
        Statement:
          - Sid: EnableScanOnPush
            Effect: Allow
            Principal: '*'
            Action:
              - ecr:GetRegistryScanningConfiguration
              - ecr:PutRegistryScanningConfiguration

  # Step 2: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 3: EventBridge rule for image scan findings
  ImageScanRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.ecr]
        detail-type: [ECR Image Scan]
        detail:
          finding-severity-counts:
            CRITICAL: [{numeric: [">", 0]}]
      Targets:
        - Id: Email
          Arn: !Ref AlertTopic

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
                terraform_template="""# ECR image scanning for execution hijacking detection

variable "alert_email" {
  type = string
}

# Step 1: Enable ECR enhanced scanning
resource "aws_ecr_registry_scanning_configuration" "main" {
  scan_type = "ENHANCED"

  rule {
    scan_frequency = "SCAN_ON_PUSH"
    repository_filter {
      filter      = "*"
      filter_type = "WILDCARD"
    }
  }
}

# Step 2: SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "ecr-image-scan-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 3: EventBridge rule for critical findings
resource "aws_cloudwatch_event_rule" "image_scan" {
  name = "ecr-critical-vulnerabilities"
  event_pattern = jsonencode({
    source      = ["aws.ecr"]
    detail-type = ["ECR Image Scan"]
    detail = {
      finding-severity-counts = {
        CRITICAL = [{ numeric = [">", 0] }]
      }
    }
  })
}

resource "aws_sqs_queue" "dlq" {
  name                      = "hijack-execution-dlq"
  message_retention_seconds = 1209600
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.image_scan.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
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
          "aws:SourceArn" = aws_cloudwatch_event_rule.image_scan.arn
        }
      }
    }]
  })
}

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
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="ECR: Critical Vulnerabilities in Container Image",
                alert_description_template=(
                    "Container image {imageId} has critical vulnerabilities that could enable "
                    "execution flow hijacking. Repository: {repositoryName}."
                ),
                investigation_steps=[
                    "Review ECR scan findings for specific vulnerabilities",
                    "Check if vulnerable libraries match known hijacking patterns",
                    "Identify which containers are running the affected image",
                    "Review image build process for supply chain compromise",
                    "Check image signature and verify image provenance",
                ],
                containment_actions=[
                    "Prevent deployment of vulnerable images using admission controllers",
                    "Update base images and rebuild containers",
                    "Implement image signing and verification",
                    "Enable GuardDuty Runtime Monitoring for running containers",
                    "Quarantine affected images in ECR",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Set severity thresholds based on risk tolerance; suppress known acceptable vulnerabilities",
            detection_coverage="70% - detects known vulnerable libraries",
            evasion_considerations="Zero-day exploits and custom malware may not be detected",
            implementation_effort=EffortLevel.LOW,
            implementation_time="45 minutes",
            estimated_monthly_cost="$0.09 per image scan",
            prerequisites=["ECR repository with images"],
        ),
        # Strategy 2: AWS - Instance Userdata Modification
        DetectionStrategy(
            strategy_id="t1574-aws-userdata-mod",
            name="EC2 Instance Userdata Modification Detection",
            description=(
                "Detect when EC2 instance userdata is modified, which could be used to "
                "hijack instance startup execution flow and achieve persistence."
            ),
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.ec2"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventSource": ["ec2.amazonaws.com"],
                        "eventName": ["ModifyInstanceAttribute"],
                    },
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect EC2 userdata modifications for execution hijacking

Parameters:
  SNSTopicArn:
    Type: String

Resources:
  UserdataModRule:
    Type: AWS::Events::Rule
    Properties:
      Name: T1574-UserdataModification
      Description: Detect EC2 instance userdata modifications
      EventPattern:
        source:
          - aws.ec2
        detail-type:
          - "AWS API Call via CloudTrail"
        detail:
          eventSource:
            - ec2.amazonaws.com
          eventName:
            - ModifyInstanceAttribute
      State: ENABLED
      Targets:
        - Id: SNSAlert
          Arn: !Ref SNSTopicArn""",
                terraform_template="""# Detect EC2 userdata modifications

variable "sns_topic_arn" {
  type = string
}

resource "aws_cloudwatch_event_rule" "userdata_mod" {
  name        = "ec2-userdata-modifications"
  description = "Detect modifications to EC2 instance userdata"

  event_pattern = jsonencode({
    source      = ["aws.ec2"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["ec2.amazonaws.com"]
      eventName   = ["ModifyInstanceAttribute"]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.userdata_mod.name
  arn  = var.sns_topic_arn
}""",
                alert_severity="high",
                alert_title="EC2 Instance Userdata Modified",
                alert_description_template=(
                    "EC2 instance userdata was modified for instance {instanceId}. "
                    "This could indicate an attempt to hijack instance startup execution. "
                    "User: {userIdentity.principalId}, Source IP: {sourceIPAddress}."
                ),
                investigation_steps=[
                    "Review the new userdata content for malicious commands",
                    "Check if the modification was authorised",
                    "Identify who made the change and verify their credentials",
                    "Review CloudTrail for other suspicious activity from this principal",
                    "Check if instance has been rebooted since modification",
                ],
                containment_actions=[
                    "Stop the affected instance if compromised",
                    "Revert userdata to known-good configuration",
                    "Review and rotate compromised credentials",
                    "Enable IMDSv2 to prevent metadata exploitation",
                    "Implement Systems Manager for secure configuration management",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist authorised configuration management tools and CI/CD pipelines",
            detection_coverage="95% - catches all userdata modification API calls",
            evasion_considerations="Attacker may modify userdata before CloudTrail is enabled",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled", "EventBridge configured"],
        ),
        # Strategy 3: AWS - Runtime Process Execution Monitoring
        DetectionStrategy(
            strategy_id="t1574-aws-runtime-monitor",
            name="GuardDuty Runtime Monitoring for Suspicious Processes",
            description=(
                "GuardDuty Runtime Monitoring detects suspicious process execution patterns "
                "that may indicate execution flow hijacking, including unusual library loads "
                "and process injections."
            ),
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "Execution:Runtime/SuspiciousCommand",
                    "Execution:Runtime/NewBinaryExecuted",
                    "Execution:Runtime/NewLibraryLoaded",
                    "PrivilegeEscalation:Runtime/ContainerMountsHostDirectory",
                ],
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: GuardDuty Runtime Monitoring for execution hijacking

Parameters:
  AlertEmail:
    Type: String

Resources:
  # Step 1: GuardDuty detector (if not exists)
  GuardDutyDetector:
    Type: AWS::GuardDuty::Detector
    Properties:
      Enable: true
      Features:
        - Name: RUNTIME_MONITORING
          Status: ENABLED

  # Step 2: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 3: EventBridge rule for runtime findings
  RuntimeFindingsRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.guardduty]
        detail-type:
          - GuardDuty Finding
        detail:
          type:
            - prefix: "Execution:Runtime"
            - prefix: "PrivilegeEscalation:Runtime"
      Targets:
        - Id: Email
          Arn: !Ref AlertTopic

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
                terraform_template="""# GuardDuty Runtime Monitoring for execution hijacking

variable "alert_email" {
  type = string
}

# Step 1: Enable GuardDuty with Runtime Monitoring
resource "aws_guardduty_detector" "main" {
  enable = true

  datasources {
    kubernetes {
      audit_logs {
        enable = true
      }
    }
  }
}

# Step 2: SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "guardduty-runtime-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 3: EventBridge rule for runtime execution findings
resource "aws_cloudwatch_event_rule" "runtime_findings" {
  name = "guardduty-execution-hijacking"
  event_pattern = jsonencode({
    source = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    detail = {
      type = [
        { prefix = "Execution:Runtime" },
        { prefix = "PrivilegeEscalation:Runtime" }
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.runtime_findings.name
  arn  = aws_sns_topic.alerts.arn
}

resource "aws_sns_topic_policy" "allow_eventbridge" {
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
      }
    }]
  })
}""",
                alert_severity="critical",
                alert_title="GuardDuty: Suspicious Runtime Execution Detected",
                alert_description_template=(
                    "GuardDuty detected suspicious runtime execution: {finding_type}. "
                    "Resource: {resource.instanceDetails.instanceId or resource.eksClusterDetails.name}. "
                    "This may indicate execution flow hijacking."
                ),
                investigation_steps=[
                    "Review GuardDuty finding details for specific indicators",
                    "Check process tree to identify parent and child processes",
                    "Examine loaded libraries for suspicious or unexpected paths",
                    "Review file system for modified binaries or libraries",
                    "Correlate with network activity for command and control",
                    "Check container image provenance and scan results",
                ],
                containment_actions=[
                    "Isolate affected instance or container immediately",
                    "Capture memory dump and forensic snapshot",
                    "Terminate compromised processes",
                    "Rebuild instance or container from known-good images",
                    "Review and update security group rules",
                    "Enable EBS encryption and snapshots for evidence",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Baseline normal runtime behaviour; suppress findings for known debugging activities",
            detection_coverage="75% - detects known execution hijacking patterns",
            evasion_considerations="Advanced attackers may use fileless techniques or legitimate binaries",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$4.60 per instance/month for Runtime Monitoring",
            prerequisites=[
                "GuardDuty enabled",
                "ECS or EKS with Runtime Monitoring enabled",
            ],
        ),
        # Strategy 4: GCP - Container Analysis and Binary Authorization
        DetectionStrategy(
            strategy_id="t1574-gcp-container-analysis",
            name="GCP Container Analysis and Binary Authorization",
            description=(
                "GCP Container Analysis scans container images for vulnerabilities and malware. "
                "Binary Authorization ensures only verified images can be deployed to GKE."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="container_analysis",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="container_analysis_note"
severity>=WARNING
protoPayload.request.vulnerability.severity=~"CRITICAL|HIGH"''',
                gcp_terraform_template="""# GCP: Container Analysis and Binary Authorization

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

variable "cluster_name" {
  type = string
}

# Step 1: Enable Container Analysis API
resource "google_project_service" "container_analysis" {
  project = var.project_id
  service = "containeranalysis.googleapis.com"
}

# Step 2: Enable Binary Authorization
resource "google_binary_authorization_policy" "policy" {
  admission_whitelist_patterns {
    name_pattern = "gcr.io/${var.project_id}/*"
  }

  default_admission_rule {
    evaluation_mode  = "REQUIRE_ATTESTATION"
    enforcement_mode = "ENFORCED_BLOCK_AND_AUDIT_LOG"
    require_attestations_by = [
      google_binary_authorization_attestor.attestor.name
    ]
  }

  cluster_admission_rules {
    cluster                 = "projects/${var.project_id}/locations/*/clusters/${var.cluster_name}"
    evaluation_mode         = "REQUIRE_ATTESTATION"
    enforcement_mode        = "ENFORCED_BLOCK_AND_AUDIT_LOG"
    require_attestations_by = [
      google_binary_authorization_attestor.attestor.name
    ]
  }
}

# Step 3: Create attestor for verified images
resource "google_binary_authorization_attestor" "attestor" {
  name = "production-attestor"
  attestation_authority_note {
    note_reference = google_container_analysis_note.note.name
  }
}

resource "google_container_analysis_note" "note" {
  name = "production-attestation-note"
  attestation_authority {
    hint {
      human_readable_name = "Production Image Attestor"
    }
  }
}

# Step 4: Notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 5: Alert for critical vulnerabilities
resource "google_logging_metric" "critical_vulns" {
  name   = "critical-container-vulnerabilities"
  filter = <<-EOT
    resource.type="container_analysis_note"
    severity>=WARNING
    protoPayload.request.vulnerability.severity=~"(CRITICAL|HIGH)"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "critical_vulns" {
  display_name = "Critical Container Vulnerabilities"
  combiner     = "OR"

  conditions {
    display_name = "Critical vulnerabilities detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.critical_vulns.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="high",
                alert_title="GCP: Critical Vulnerabilities in Container Image",
                alert_description_template=(
                    "Critical or high severity vulnerabilities detected in container image. "
                    "These could enable execution flow hijacking attacks."
                ),
                investigation_steps=[
                    "Review Container Analysis findings for specific CVEs",
                    "Check if vulnerabilities affect libraries used for dynamic loading",
                    "Identify which clusters are running vulnerable images",
                    "Review image build pipeline for supply chain risks",
                    "Verify image signatures and attestations",
                ],
                containment_actions=[
                    "Block deployment of vulnerable images using Binary Authorization",
                    "Update base images and rebuild containers",
                    "Implement continuous vulnerability scanning",
                    "Use distroless or minimal base images",
                    "Enable GKE Security Posture dashboard",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Set acceptable vulnerability severity levels; maintain exception list for accepted risks",
            detection_coverage="70% - detects known vulnerable components",
            evasion_considerations="Custom or unknown malware may not be detected by vulnerability scanners",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$0.26 per image + $5/month per policy",
            prerequisites=["GKE cluster", "Artifact Registry or Container Registry"],
        ),
        # Strategy 5: GCP - Compute Instance Metadata Modifications
        DetectionStrategy(
            strategy_id="t1574-gcp-metadata-mod",
            name="GCP Compute Instance Metadata Modification Detection",
            description=(
                "Detect when Compute Engine instance metadata is modified, which could be used "
                "to hijack instance startup scripts and achieve persistence."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="compute",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName=~"(setMetadata|setCommonInstanceMetadata)"
protoPayload.serviceName="compute.googleapis.com"
protoPayload.request.metadata.items.key=~"(startup-script|shutdown-script)"''',
                gcp_terraform_template="""# GCP: Detect instance metadata modifications

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

# Step 2: Log-based metric for metadata changes
resource "google_logging_metric" "metadata_mod" {
  name   = "instance-metadata-modifications"
  filter = <<-EOT
    protoPayload.methodName=~"(setMetadata|setCommonInstanceMetadata)"
    protoPayload.serviceName="compute.googleapis.com"
    protoPayload.request.metadata.items.key=~"(startup-script|shutdown-script)"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "metadata_mod" {
  display_name = "Compute Instance Startup Script Modified"
  combiner     = "OR"

  conditions {
    display_name = "Instance metadata modified"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.metadata_mod.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  documentation {
    content = <<-EOT
      Instance startup or shutdown scripts were modified.
      This could indicate an attempt to hijack execution flow.

      Investigation steps:
      1. Review the new script content
      2. Verify if the change was authorised
      3. Check for other suspicious activity from the same principal
    EOT
  }
}""",
                alert_severity="high",
                alert_title="GCP: Instance Startup Script Modified",
                alert_description_template=(
                    "Compute Engine instance metadata was modified. "
                    "Startup or shutdown scripts may have been changed to hijack execution."
                ),
                investigation_steps=[
                    "Review the new metadata content for malicious commands",
                    "Check if the modification was authorised",
                    "Identify the service account or user that made the change",
                    "Review audit logs for other suspicious activity",
                    "Verify current running state of the instance",
                ],
                containment_actions=[
                    "Stop the affected instance if compromised",
                    "Revert metadata to known-good configuration",
                    "Review and rotate service account keys",
                    "Implement organisation policy constraints for metadata",
                    "Use OS Config for secure configuration management",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist authorised deployment tools and infrastructure-as-code pipelines",
            detection_coverage="95% - catches all metadata modification API calls",
            evasion_considerations="Attacker may modify metadata before audit logging is enabled",
            implementation_effort=EffortLevel.LOW,
            implementation_time="45 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
    ],
    recommended_order=[
        "t1574-aws-ecr-image-scan",
        "t1574-gcp-container-analysis",
        "t1574-aws-runtime-monitor",
        "t1574-aws-userdata-mod",
        "t1574-gcp-metadata-mod",
    ],
    total_effort_hours=5.0,
    coverage_improvement="+30% improvement for Persistence and Privilege Escalation tactics",
)
