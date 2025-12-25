"""
T1003 - OS Credential Dumping

Adversaries attempt to extract credentials from OS caches, memory structures,
or storage to obtain login information and credential material.
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
    technique_id="T1003",
    technique_name="OS Credential Dumping",
    tactic_ids=["TA0006"],
    mitre_url="https://attack.mitre.org/techniques/T1003/",
    threat_context=ThreatContext(
        description=(
            "Adversaries attempt to extract credentials from OS memory structures, "
            "caches, or storage to obtain login information in hash or plaintext form. "
            "In cloud environments, this includes dumping credentials from EC2 instances, "
            "GCE VMs, container workloads, and serverless functions to enable lateral "
            "movement and access restricted information."
        ),
        attacker_goal="Extract credentials from compromised cloud instances for lateral movement",
        why_technique=[
            "Stolen credentials enable lateral movement to other cloud resources",
            "Cloud instances often store credentials for accessing other services",
            "Container and serverless credentials provide access to cloud APIs",
            "Dumped SSH keys can access other instances",
            "Instance metadata credentials can be cached in memory",
            "Database connection strings in memory contain sensitive credentials",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "Credential dumping is a critical post-compromise technique. "
            "In cloud environments, dumped credentials can provide access to "
            "databases, storage, and other cloud services, significantly expanding "
            "the attack's blast radius. Combined with overly permissive IAM roles, "
            "this technique can lead to full environment compromise."
        ),
        business_impact=[
            "Lateral movement to database servers and sensitive systems",
            "Unauthorised access to cloud storage and APIs",
            "Data exfiltration using stolen credentials",
            "Privilege escalation via compromised admin credentials",
            "Ransomware deployment across multiple systems",
        ],
        typical_attack_phase="credential_access",
        often_precedes=["T1078", "T1021", "T1210"],
        often_follows=["T1078.004", "T1190", "T1133"],
    ),
    detection_strategies=[
        # Strategy 1: EC2/GCE Process Memory Access Detection
        DetectionStrategy(
            strategy_id="t1003-memory-access",
            name="AWS GuardDuty Runtime Monitoring for Credential Dumping",
            description=(
                "AWS GuardDuty Runtime Monitoring detects suspicious process activity "
                "on EC2 instances, including attempts to access sensitive memory regions "
                "or dump credentials from running processes."
            ),
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "Execution:Runtime/ReverseShell",
                    "PrivilegeEscalation:Runtime/ContainerMountsHostDirectory",
                    "PrivilegeEscalation:Runtime/DockerSocketAccessed",
                    "Execution:Runtime/NewBinaryExecuted",
                    "CredentialAccess:Runtime/MemoryDumpCreated",
                ],
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: GuardDuty Runtime Monitoring for credential dumping detection

Parameters:
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # Step 1: Enable GuardDuty with Runtime Monitoring
  GuardDutyDetector:
    Type: AWS::GuardDuty::Detector
    Properties:
      Enable: true
      Features:
        - Name: RUNTIME_MONITORING
          Status: ENABLED

  # Step 2: Create SNS topic for alerts
  SecurityAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: Credential Dumping Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 3: Route credential access findings to email
  CredentialDumpingRule:
    Type: AWS::Events::Rule
    Properties:
      Name: T1003-CredentialDumping
      Description: Alert on credential dumping attempts
      EventPattern:
        source: [aws.guardduty]
        detail-type:
          - GuardDuty Finding
        detail:
          type:
            - prefix: "CredentialAccess:Runtime"
            - prefix: "PrivilegeEscalation:Runtime"
            - prefix: "Execution:Runtime"
      State: ENABLED
      Targets:
        - Id: AlertTopic
          Arn: !Ref SecurityAlertTopic

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref SecurityAlertTopic]
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref SecurityAlertTopic""",
                terraform_template="""# GuardDuty Runtime Monitoring for credential dumping

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: Enable GuardDuty with Runtime Monitoring
resource "aws_guardduty_detector" "main" {
  enable = true

  datasources {
    s3_logs {
      enable = true
    }
    kubernetes {
      audit_logs {
        enable = true
      }
    }
  }
}

# Enable Runtime Monitoring for EC2 instances
resource "aws_guardduty_detector_feature" "runtime_monitoring" {
  detector_id = aws_guardduty_detector.main.id
  name        = "RUNTIME_MONITORING"
  status      = "ENABLED"
}

# Step 2: Create SNS topic for alerts
resource "aws_sns_topic" "credential_dumping_alerts" {
  name         = "credential-dumping-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "Credential Dumping Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.credential_dumping_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 3: Route credential access findings to email
resource "aws_cloudwatch_event_rule" "credential_dumping" {
  name        = "guardduty-credential-dumping"
  description = "Alert on credential dumping attempts"
  event_pattern = jsonencode({
    source = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    detail = {
      type = [
        { prefix = "CredentialAccess:Runtime" },
        { prefix = "PrivilegeEscalation:Runtime" },
        { prefix = "Execution:Runtime" }
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.credential_dumping.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.credential_dumping_alerts.arn
}

resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.credential_dumping_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.credential_dumping_alerts.arn
    }]
  })
}""",
                alert_severity="critical",
                alert_title="GuardDuty: Credential Dumping Activity Detected",
                alert_description_template=(
                    "Suspicious credential dumping activity detected on instance {instance_id}. "
                    "Finding: {finding_type}. Process: {process_name}. "
                    "This may indicate an active breach attempt."
                ),
                investigation_steps=[
                    "Review the GuardDuty finding details and affected instance",
                    "Check CloudTrail for API calls from the instance role",
                    "Examine running processes on the instance using SSM Session Manager",
                    "Review instance security group rules and network connections",
                    "Check if any credentials or secrets were accessed from Secrets Manager or Parameter Store",
                    "Investigate recent SSH or RDP sessions to the instance",
                ],
                containment_actions=[
                    "Isolate the instance by modifying security group to block all traffic",
                    "Create a forensic snapshot of the instance for investigation",
                    "Rotate all credentials that may have been on the instance",
                    "Revoke the instance IAM role session",
                    "Terminate the instance if compromise is confirmed",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Exclude known administrative tools; baseline normal debugging activities",
            detection_coverage="70% - detects runtime credential access patterns",
            evasion_considerations="Attackers may use obfuscated tool names or fileless techniques",
            implementation_effort=EffortLevel.LOW,
            implementation_time="45 minutes",
            estimated_monthly_cost="$4.60 per instance per month for Runtime Monitoring",
            prerequisites=[
                "GuardDuty enabled",
                "SSM Agent on EC2 instances for Runtime Monitoring",
            ],
        ),
        # Strategy 2: Suspicious Process Execution via CloudWatch
        DetectionStrategy(
            strategy_id="t1003-suspicious-tools",
            name="Detect Credential Dumping Tools via CloudWatch Logs",
            description=(
                "Monitor CloudWatch Logs from instances for execution of known credential "
                "dumping tools such as mimikatz, procdump, hashdump, and similar utilities."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, @message, instanceId, processName, commandLine
| filter @message like /mimikatz|procdump|pwdump|hashdump|gsecdump|lsadump|sekurlsa|SafetyKatz|Out-Minidump/
| stats count() as executions by instanceId, processName, bin(5m)
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect credential dumping tool execution

Parameters:
  CloudWatchLogGroup:
    Type: String
    Description: Log group containing instance logs
  SNSTopicArn:
    Type: String
    Description: SNS topic for alerts

Resources:
  # Step 1: Create metric filter for credential dumping tools
  CredDumpToolFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudWatchLogGroup
      FilterPattern: '[time, instance, process, command="*mimikatz*" || command="*procdump*" || command="*pwdump*" || command="*hashdump*" || command="*lsadump*"]'
      MetricTransformations:
        - MetricName: CredentialDumpingTools
          MetricNamespace: Security/T1003
          MetricValue: "1"

  # Step 2: Create alarm for tool execution
  CredDumpAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1003-CredentialDumpingTool
      AlarmDescription: Credential dumping tool detected
      MetricName: CredentialDumpingTools
      Namespace: Security/T1003
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 1
      ComparisonOperator: GreaterThanOrEqualToThreshold
      AlarmActions:
        - !Ref SNSTopicArn

  # Step 3: Create subscription filter for immediate alerting
  SubscriptionFilter:
    Type: AWS::Logs::SubscriptionFilter
    Properties:
      LogGroupName: !Ref CloudWatchLogGroup
      FilterPattern: '[time, instance, process, command="*mimikatz*" || command="*procdump*"]'
      DestinationArn: !Ref SNSTopicArn""",
                terraform_template="""# Detect credential dumping tool execution

variable "cloudwatch_log_group" {
  type        = string
  description = "Log group containing instance logs"
}

variable "alert_email" {
  type        = string
  description = "Email for alerts"
}

# Step 1: Create metric filter for credential dumping tools
resource "aws_cloudwatch_log_metric_filter" "credential_dumping_tools" {
  name           = "credential-dumping-tools"
  log_group_name = var.cloudwatch_log_group
  pattern        = "[time, instance, process, command=\"*mimikatz*\" || command=\"*procdump*\" || command=\"*pwdump*\" || command=\"*hashdump*\" || command=\"*lsadump*\"]"

  metric_transformation {
    name      = "CredentialDumpingTools"
    namespace = "Security/T1003"
    value     = "1"
  }
}

# Step 2: Create SNS topic
resource "aws_sns_topic" "alerts" {
  name = "credential-dumping-tool-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 3: Create alarm for tool execution
resource "aws_cloudwatch_metric_alarm" "credential_dumping" {
  alarm_name          = "T1003-CredentialDumpingTool"
  alarm_description   = "Credential dumping tool detected"
  metric_name         = "CredentialDumpingTools"
  namespace           = "Security/T1003"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="critical",
                alert_title="Credential Dumping Tool Detected",
                alert_description_template=(
                    "Known credential dumping tool detected on instance {instance_id}. "
                    "Process: {process_name}. Command: {command_line}. "
                    "Immediate investigation required."
                ),
                investigation_steps=[
                    "Identify the exact tool and command executed",
                    "Check process parent and child relationships",
                    "Review user session that executed the command",
                    "Search for exfiltration of dumped credential files",
                    "Check for lateral movement attempts following the execution",
                    "Review all file system changes on the instance",
                ],
                containment_actions=[
                    "Immediately isolate the instance from the network",
                    "Kill the credential dumping process if still running",
                    "Rotate all credentials that may have been accessed",
                    "Search for and delete any credential dump files",
                    "Force logout all active user sessions on affected systems",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist authorised security testing activities with approval workflow",
            detection_coverage="85% - requires CloudWatch agent with command logging enabled",
            evasion_considerations="Custom or renamed tools may evade signature detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-15 depending on log volume",
            prerequisites=[
                "CloudWatch Logs Agent installed on instances",
                "Process execution logging enabled",
            ],
        ),
        # Strategy 3: Container Credential Access
        DetectionStrategy(
            strategy_id="t1003-container-creds",
            name="Detect Container Credential Dumping",
            description=(
                "Monitor for suspicious access to container secrets, environment variables, "
                "and mounted credential files in ECS, EKS, or GKE environments."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, kubernetes.pod_name, kubernetes.namespace_name, @message
| filter @message like /run.secrets|var.run.secrets|AWS_ACCESS_KEY|AWS_SECRET|printenv|env |cat.*credentials|grep.*password/
| stats count() as secret_access by kubernetes.pod_name, kubernetes.namespace_name, bin(10m)
| filter secret_access > 5
| sort @timestamp desc""",
                cloudformation_template='''AWSTemplateFormatVersion: '2010-09-09'
Description: Detect container credential dumping in EKS

Parameters:
  EKSLogGroup:
    Type: String
    Description: CloudWatch log group for EKS cluster
    Default: /aws/eks/cluster/logs
  SNSTopicArn:
    Type: String

Resources:
  # Step 1: Create metric filter for secret access
  ContainerSecretAccessFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref EKSLogGroup
      FilterPattern: '[time, stream, pod, msg="*/run/secrets*" || msg="*AWS_ACCESS_KEY*" || msg="*printenv*"]'
      MetricTransformations:
        - MetricName: ContainerSecretAccess
          MetricNamespace: Security/T1003
          MetricValue: "1"

  # Step 2: Create alarm for excessive secret access
  SecretAccessAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1003-ContainerCredentialDumping
      AlarmDescription: Container accessing secrets suspiciously
      MetricName: ContainerSecretAccess
      Namespace: Security/T1003
      Statistic: Sum
      Period: 600
      EvaluationPeriods: 1
      Threshold: 5
      ComparisonOperator: GreaterThanThreshold
      AlarmActions:
        - !Ref SNSTopicArn

  # Step 3: Monitor privileged container execution
  PrivilegedContainerFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref EKSLogGroup
      FilterPattern: '[time, stream, msg="*privileged*true*" || msg="*hostPID*true*"]'
      MetricTransformations:
        - MetricName: PrivilegedContainerExecution
          MetricNamespace: Security/T1003
          MetricValue: "1"''',
                terraform_template="""# Detect container credential dumping in EKS

variable "eks_log_group" {
  type        = string
  description = "CloudWatch log group for EKS cluster"
  default     = "/aws/eks/cluster/logs"
}

variable "alert_email" {
  type = string
}

resource "aws_sns_topic" "alerts" {
  name = "container-credential-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 1: Create metric filter for secret access
resource "aws_cloudwatch_log_metric_filter" "container_secret_access" {
  name           = "container-secret-access"
  log_group_name = var.eks_log_group
  pattern        = "[time, stream, pod, msg=\"*/run/secrets*\" || msg=\"*AWS_ACCESS_KEY*\" || msg=\"*printenv*\"]"

  metric_transformation {
    name      = "ContainerSecretAccess"
    namespace = "Security/T1003"
    value     = "1"
  }
}

# Step 2: Create alarm for excessive secret access
resource "aws_cloudwatch_metric_alarm" "secret_access" {
  alarm_name          = "T1003-ContainerCredentialDumping"
  alarm_description   = "Container accessing secrets suspiciously"
  metric_name         = "ContainerSecretAccess"
  namespace           = "Security/T1003"
  statistic           = "Sum"
  period              = 600
  evaluation_periods  = 1
  threshold           = 5
  comparison_operator = "GreaterThanThreshold"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

# Step 3: Monitor privileged container execution
resource "aws_cloudwatch_log_metric_filter" "privileged_containers" {
  name           = "privileged-container-execution"
  log_group_name = var.eks_log_group
  pattern        = "[time, stream, msg=\"*privileged*true*\" || msg=\"*hostPID*true*\"]"

  metric_transformation {
    name      = "PrivilegedContainerExecution"
    namespace = "Security/T1003"
    value     = "1"
  }
}""",
                alert_severity="high",
                alert_title="Container Credential Dumping Detected",
                alert_description_template=(
                    "Suspicious credential access detected in container {pod_name}. "
                    "Namespace: {namespace}. Multiple secret access attempts observed."
                ),
                investigation_steps=[
                    "Identify the pod and container accessing credentials",
                    "Review the container image and its source",
                    "Check pod security context and capabilities",
                    "Examine container network connections",
                    "Review service account permissions attached to the pod",
                    "Check for other pods from the same deployment",
                ],
                containment_actions=[
                    "Delete the suspicious pod immediately",
                    "Review and update the container image",
                    "Rotate all Kubernetes secrets in the namespace",
                    "Review and restrict service account permissions",
                    "Implement Pod Security Standards to prevent privileged containers",
                    "Enable network policies to restrict pod communication",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal secret access patterns for each application",
            detection_coverage="65% - requires container runtime logging enabled",
            evasion_considerations="Attackers may use volume mounts or process injection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$10-25",
            prerequisites=[
                "EKS cluster with CloudWatch Container Insights",
                "Application logging enabled",
            ],
        ),
        # Strategy 4: GCP Instance Credential Access
        DetectionStrategy(
            strategy_id="t1003-gcp-credentials",
            name="GCP: Detect Credential Dumping on GCE Instances",
            description=(
                "Monitor GCP Cloud Logging for credential dumping activity on "
                "Compute Engine instances and GKE nodes."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_instance"
(protoPayload.request.commandLine=~"mimikatz|procdump|hashdump|lsadump"
OR textPayload=~"/var/lib/docker|/run/secrets|gcloud.*credentials")""",
                gcp_terraform_template="""# GCP: Detect credential dumping on GCE instances

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type = string
}

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "email" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log-based metric for credential dumping
resource "google_logging_metric" "credential_dumping" {
  project = var.project_id
  name    = "credential-dumping-attempts"
  filter  = <<-EOT
    resource.type="gce_instance"
    (protoPayload.request.commandLine=~"mimikatz|procdump|hashdump|lsadump"
    OR textPayload=~"/var/lib/docker|/run/secrets|gcloud.*credentials")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "instance_id"
      value_type  = "STRING"
      description = "Instance where credential dumping was detected"
    }
  }

  label_extractors = {
    instance_id = "EXTRACT(resource.labels.instance_id)"
  }
}

# Step 3: Create alert policy
resource "google_monitoring_alert_policy" "credential_dumping" {
  project      = var.project_id
  display_name = "T1003: Credential Dumping Detected"
  combiner     = "OR"
  conditions {
    display_name = "Credential dumping activity"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.credential_dumping.name}\" resource.type=\"gce_instance\""
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
    auto_close = "1800s"
  }
  documentation {
    content   = "Credential dumping activity detected on GCE instance. Investigate immediately."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="critical",
                alert_title="GCP: Credential Dumping Detected",
                alert_description_template=(
                    "Credential dumping activity detected on GCE instance {instance_id}. "
                    "Command: {command_line}. Investigate immediately."
                ),
                investigation_steps=[
                    "Review the Cloud Logging entry for full command details",
                    "Check the instance's service account permissions",
                    "Review recent API calls made by the instance's service account",
                    "Examine network connections from the instance",
                    "Check for any data exfiltration to external IPs",
                    "Review VPC Flow Logs for suspicious traffic patterns",
                ],
                containment_actions=[
                    "Stop the GCE instance to prevent further compromise",
                    "Create a snapshot for forensic analysis",
                    "Revoke the instance's service account credentials",
                    "Update firewall rules to isolate the instance",
                    "Rotate any secrets the instance had access to",
                    "Review and remove any unauthorised persistent access mechanisms",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Exclude authorised penetration testing with documented approval",
            detection_coverage="75% - requires Ops Agent with process monitoring",
            evasion_considerations="Custom tools or obfuscation may bypass pattern matching",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1.5 hours",
            estimated_monthly_cost="$15-30",
            prerequisites=[
                "Cloud Logging API enabled",
                "Ops Agent installed on GCE instances",
            ],
        ),
        # Strategy 5: Secrets Manager Access Patterns
        DetectionStrategy(
            strategy_id="t1003-secrets-access",
            name="Unusual Secrets Manager Access Pattern Detection",
            description=(
                "Detect bulk or unusual access to AWS Secrets Manager or Parameter Store "
                "that may indicate credential harvesting from a compromised instance."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.principalId, eventName, requestParameters.secretId, sourceIPAddress
| filter eventSource in ["secretsmanager.amazonaws.com", "ssm.amazonaws.com"]
| filter eventName in ["GetSecretValue", "GetParameter", "GetParameters", "GetParametersByPath"]
| stats count() as access_count, count_distinct(coalesce(requestParameters.secretId, requestParameters.name)) as unique_secrets
  by userIdentity.principalId, sourceIPAddress, bin(10m)
| filter access_count > 10 or unique_secrets > 5
| sort access_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect unusual Secrets Manager access patterns

Parameters:
  CloudTrailLogGroup:
    Type: String
    Description: CloudTrail log group name
  SNSTopicArn:
    Type: String
    Description: SNS topic for alerts

Resources:
  # Step 1: Monitor Secrets Manager access
  SecretsAccessFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventSource = "secretsmanager.amazonaws.com" && $.eventName = "GetSecretValue" }'
      MetricTransformations:
        - MetricName: SecretsManagerAccess
          MetricNamespace: Security/T1003
          MetricValue: "1"

  # Step 2: Monitor Parameter Store access
  ParameterStoreFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventSource = "ssm.amazonaws.com" && ($.eventName = "GetParameter" || $.eventName = "GetParameters") }'
      MetricTransformations:
        - MetricName: ParameterStoreAccess
          MetricNamespace: Security/T1003
          MetricValue: "1"

  # Step 3: Alert on excessive access
  BulkSecretsAccessAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1003-BulkSecretsAccess
      AlarmDescription: Bulk access to secrets detected
      MetricName: SecretsManagerAccess
      Namespace: Security/T1003
      Statistic: Sum
      Period: 600
      EvaluationPeriods: 1
      Threshold: 10
      ComparisonOperator: GreaterThanThreshold
      AlarmActions:
        - !Ref SNSTopicArn""",
                terraform_template="""# Detect unusual Secrets Manager access patterns

variable "cloudtrail_log_group" {
  type = string
}

variable "alert_email" {
  type = string
}

resource "aws_sns_topic" "alerts" {
  name = "secrets-access-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 1: Monitor Secrets Manager access
resource "aws_cloudwatch_log_metric_filter" "secrets_access" {
  name           = "bulk-secrets-access"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventSource = \"secretsmanager.amazonaws.com\" && $.eventName = \"GetSecretValue\" }"

  metric_transformation {
    name      = "SecretsManagerAccess"
    namespace = "Security/T1003"
    value     = "1"
  }
}

# Step 2: Monitor Parameter Store access
resource "aws_cloudwatch_log_metric_filter" "parameter_store_access" {
  name           = "bulk-parameter-access"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventSource = \"ssm.amazonaws.com\" && ($.eventName = \"GetParameter\" || $.eventName = \"GetParameters\") }"

  metric_transformation {
    name      = "ParameterStoreAccess"
    namespace = "Security/T1003"
    value     = "1"
  }
}

# Step 3: Alert on excessive access
resource "aws_cloudwatch_metric_alarm" "bulk_secrets_access" {
  alarm_name          = "T1003-BulkSecretsAccess"
  alarm_description   = "Bulk access to secrets detected"
  metric_name         = "SecretsManagerAccess"
  namespace           = "Security/T1003"
  statistic           = "Sum"
  period              = 600
  evaluation_periods  = 1
  threshold           = 10
  comparison_operator = "GreaterThanThreshold"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="high",
                alert_title="Bulk Secrets Access Detected",
                alert_description_template=(
                    "Unusual secrets access pattern detected. Principal: {principal_id}. "
                    "Accessed {unique_secrets} secrets in 10 minutes. "
                    "Source IP: {source_ip}. May indicate credential harvesting."
                ),
                investigation_steps=[
                    "Identify the IAM principal accessing the secrets",
                    "Review if the access pattern is normal for this principal",
                    "Check which specific secrets were accessed",
                    "Determine if the source IP is expected",
                    "Review what the principal did after accessing secrets",
                    "Check for signs of lateral movement or data exfiltration",
                ],
                containment_actions=[
                    "Rotate all accessed secrets immediately",
                    "Revoke the IAM principal's credentials",
                    "Review and restrict IAM policies granting secrets access",
                    "Enable automatic secret rotation",
                    "Implement resource-based policies on sensitive secrets",
                    "Enable VPC endpoints for Secrets Manager to restrict network access",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal access patterns for automation and deployment systems",
            detection_coverage="60% - API-level only, cannot detect in-memory credential theft",
            evasion_considerations="Slow access over extended time periods may evade thresholds",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=[
                "CloudTrail enabled",
                "Secrets Manager/Parameter Store in use",
            ],
        ),
    ],
    recommended_order=[
        "t1003-memory-access",
        "t1003-suspicious-tools",
        "t1003-secrets-access",
        "t1003-container-creds",
        "t1003-gcp-credentials",
    ],
    total_effort_hours=7.0,
    coverage_improvement="+30% improvement for Credential Access tactic",
)
