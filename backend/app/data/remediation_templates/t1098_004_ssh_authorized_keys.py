"""
T1098.004 - Account Manipulation: SSH Authorized Keys

Adversaries modify SSH authorized_keys files to maintain persistence on victim hosts.
Used by Earth Lusca, Salt Typhoon, TeamTNT, and XCSSET malware.
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
    technique_id="T1098.004",
    technique_name="Account Manipulation: SSH Authorized Keys",
    tactic_ids=["TA0003", "TA0006"],
    mitre_url="https://attack.mitre.org/techniques/T1098/004/",
    threat_context=ThreatContext(
        description=(
            "Adversaries modify SSH authorized_keys files to maintain persistence on compromised hosts. "
            "They add attacker-controlled public keys to files like ~/.ssh/authorized_keys or "
            "/etc/ssh/keys-<username>/authorized_keys, enabling passwordless authentication. "
            "In cloud environments, attackers may abuse metadata APIs or CLI tools to inject SSH keys "
            "into EC2 instances, GCE VMs, or cloud-init configurations for persistent access."
        ),
        attacker_goal="Establish persistent SSH access to compromised instances without requiring passwords",
        why_technique=[
            "Enables persistent access that survives password changes",
            "Difficult to detect without file integrity monitoring",
            "Appears as legitimate SSH authentication",
            "Cloud metadata APIs can inject keys without host access",
            "Common in containerised environments and bastion hosts",
            "Often overlooked in incident response procedures",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=7,
        severity_reasoning=(
            "SSH key manipulation is a stealthy persistence technique that can survive password "
            "rotations and system reboots. In cloud environments, it can bypass IAM credential "
            "rotations and provide direct instance access. The technique is particularly dangerous "
            "because SSH access is often trusted and less scrutinised than other authentication methods."
        ),
        business_impact=[
            "Persistent unauthorised access to cloud instances",
            "Bypass of credential rotation policies",
            "Lateral movement to other SSH-accessible systems",
            "Data exfiltration via established SSH tunnels",
            "Privilege escalation through root SSH access",
            "Compliance violations for unauthorised access",
        ],
        typical_attack_phase="persistence",
        often_precedes=["T1021.004", "T1041", "T1005"],
        often_follows=["T1078.004", "T1190", "T1133", "T1210"],
    ),
    detection_strategies=[
        # Strategy 1: File Integrity Monitoring for authorized_keys
        DetectionStrategy(
            strategy_id="t1098004-file-integrity",
            name="AWS File Integrity Monitoring for SSH Authorized Keys",
            description=(
                "Monitor modifications to SSH authorized_keys files using CloudWatch Logs "
                "and file integrity monitoring to detect unauthorised key additions."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, @message, instanceId, filePath, changeType, userName
| filter @message like /authorized_keys/
| filter changeType in ["created", "modified", "written"]
| stats count() as modifications by instanceId, filePath, userName, bin(5m)
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Monitor SSH authorized_keys file modifications

Parameters:
  CloudWatchLogGroup:
    Type: String
    Description: Log group containing file integrity monitoring logs
    Default: /aws/ec2/file-integrity
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # Step 1: Create SNS topic for alerts
  AuthorizedKeysAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: SSH Authorized Keys Modification Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Create metric filter for authorized_keys changes
  AuthorizedKeysFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudWatchLogGroup
      FilterPattern: '[time, instance, action, file="*authorized_keys*"]'
      MetricTransformations:
        - MetricName: AuthorizedKeysModifications
          MetricNamespace: Security/T1098.004
          MetricValue: "1"

  # Step 3: Create alarm for unauthorized_keys modifications
  AuthorizedKeysAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1098.004-SSHKeyModification
      AlarmDescription: SSH authorized_keys file was modified
      MetricName: AuthorizedKeysModifications
      Namespace: Security/T1098.004
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 1
      ComparisonOperator: GreaterThanOrEqualToThreshold
      AlarmActions:
        - !Ref AuthorizedKeysAlertTopic

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref AuthorizedKeysAlertTopic]
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: cloudwatch.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AuthorizedKeysAlertTopic""",
                terraform_template="""# Monitor SSH authorized_keys file modifications

variable "cloudwatch_log_group" {
  type        = string
  description = "Log group containing file integrity monitoring logs"
  default     = "/aws/ec2/file-integrity"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "authorized_keys_alerts" {
  name         = "ssh-authorized-keys-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "SSH Authorized Keys Modification Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.authorized_keys_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for authorized_keys changes
resource "aws_cloudwatch_log_metric_filter" "authorized_keys" {
  name           = "ssh-authorized-keys-modifications"
  log_group_name = var.cloudwatch_log_group
  pattern        = "[time, instance, action, file=\"*authorized_keys*\"]"

  metric_transformation {
    name      = "AuthorizedKeysModifications"
    namespace = "Security/T1098.004"
    value     = "1"
  }
}

# Step 3: Create alarm for authorized_keys modifications
resource "aws_cloudwatch_metric_alarm" "authorized_keys" {
  alarm_name          = "T1098.004-SSHKeyModification"
  alarm_description   = "SSH authorized_keys file was modified"
  metric_name         = "AuthorizedKeysModifications"
  namespace           = "Security/T1098.004"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  alarm_actions       = [aws_sns_topic.authorized_keys_alerts.arn]
}""",
                alert_severity="high",
                alert_title="SSH Authorized Keys File Modified",
                alert_description_template=(
                    "SSH authorized_keys file was modified on instance {instance_id}. "
                    "File path: {file_path}. User: {user_name}. "
                    "This may indicate an attempt to establish persistent access."
                ),
                investigation_steps=[
                    "Review the CloudWatch Logs entry for the exact file modification details",
                    "Check which user account's authorized_keys file was modified",
                    "Examine the contents of the authorized_keys file for unknown public keys",
                    "Review recent SSH authentication logs for successful logins using the new key",
                    "Check CloudTrail for API calls that may have modified instance metadata",
                    "Investigate the process and parent process that modified the file",
                    "Review other instances for similar unauthorized_keys modifications",
                ],
                containment_actions=[
                    "Remove unauthorized SSH public keys from authorized_keys files",
                    "Review and backup current authorized_keys files across all instances",
                    "Terminate active SSH sessions from unknown sources",
                    "Isolate the affected instance by modifying security groups",
                    "Rotate credentials and SSH keys for legitimate users",
                    "Enable SSH key-based authentication logging",
                    "Implement file integrity monitoring if not already enabled",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude authorised configuration management tools (Ansible, Chef, Puppet) with documented approval",
            detection_coverage="85% - detects direct file modifications",
            evasion_considerations="Attackers may modify files during normal configuration management windows",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1.5-2 hours",
            estimated_monthly_cost="$5-15 depending on instance count",
            prerequisites=[
                "CloudWatch Logs Agent installed",
                "File integrity monitoring configured",
                "Process execution logging enabled",
            ],
        ),
        # Strategy 2: EC2 Instance Metadata SSH Key Injection
        DetectionStrategy(
            strategy_id="t1098004-metadata-injection",
            name="Detect SSH Key Injection via EC2 Metadata API",
            description=(
                "Monitor EC2 instance metadata service calls that add SSH keys to instances. "
                "Detects use of ModifyInstanceAttribute API calls to inject public keys."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.principalId, eventName, requestParameters.instanceId, requestParameters.attribute
| filter eventSource = "ec2.amazonaws.com"
| filter eventName in ["ModifyInstanceAttribute", "ImportKeyPair", "CreateKeyPair"]
| filter requestParameters.attribute = "userData" or eventName like /KeyPair/
| stats count() as api_calls by userIdentity.principalId, eventName, requestParameters.instanceId, bin(10m)
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect SSH key injection via EC2 metadata

Parameters:
  CloudTrailLogGroup:
    Type: String
    Description: CloudTrail log group name
  SNSTopicArn:
    Type: String
    Description: SNS topic for alerts

Resources:
  # Step 1: Monitor ModifyInstanceAttribute for userData changes
  UserDataModificationFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventSource = "ec2.amazonaws.com" && $.eventName = "ModifyInstanceAttribute" && $.requestParameters.attribute = "userData" }'
      MetricTransformations:
        - MetricName: UserDataModification
          MetricNamespace: Security/T1098.004
          MetricValue: "1"

  # Step 2: Monitor SSH key pair operations
  KeyPairOperationsFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventSource = "ec2.amazonaws.com" && ($.eventName = "ImportKeyPair" || $.eventName = "CreateKeyPair") }'
      MetricTransformations:
        - MetricName: KeyPairOperations
          MetricNamespace: Security/T1098.004
          MetricValue: "1"

  # Step 3: Create alarm for metadata injection attempts
  MetadataInjectionAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1098.004-MetadataSSHKeyInjection
      AlarmDescription: SSH key injection via metadata detected
      MetricName: UserDataModification
      Namespace: Security/T1098.004
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 1
      ComparisonOperator: GreaterThanOrEqualToThreshold
      AlarmActions:
        - !Ref SNSTopicArn""",
                terraform_template="""# Detect SSH key injection via EC2 metadata

variable "cloudtrail_log_group" {
  type        = string
  description = "CloudTrail log group name"
}

variable "alert_email" {
  type        = string
  description = "Email for alerts"
}

resource "aws_sns_topic" "alerts" {
  name = "ssh-key-injection-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 1: Monitor ModifyInstanceAttribute for userData changes
resource "aws_cloudwatch_log_metric_filter" "userdata_modification" {
  name           = "userdata-ssh-key-injection"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventSource = \"ec2.amazonaws.com\" && $.eventName = \"ModifyInstanceAttribute\" && $.requestParameters.attribute = \"userData\" }"

  metric_transformation {
    name      = "UserDataModification"
    namespace = "Security/T1098.004"
    value     = "1"
  }
}

# Step 2: Monitor SSH key pair operations
resource "aws_cloudwatch_log_metric_filter" "keypair_operations" {
  name           = "ssh-keypair-operations"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventSource = \"ec2.amazonaws.com\" && ($.eventName = \"ImportKeyPair\" || $.eventName = \"CreateKeyPair\") }"

  metric_transformation {
    name      = "KeyPairOperations"
    namespace = "Security/T1098.004"
    value     = "1"
  }
}

# Step 3: Create alarm for metadata injection attempts
resource "aws_cloudwatch_metric_alarm" "metadata_injection" {
  alarm_name          = "T1098.004-MetadataSSHKeyInjection"
  alarm_description   = "SSH key injection via metadata detected"
  metric_name         = "UserDataModification"
  namespace           = "Security/T1098.004"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="high",
                alert_title="SSH Key Injection via EC2 Metadata Detected",
                alert_description_template=(
                    "Suspicious EC2 API call detected: {event_name} by {principal_id}. "
                    "Instance: {instance_id}. This may indicate SSH key injection for persistence."
                ),
                investigation_steps=[
                    "Review CloudTrail for the complete API call details",
                    "Identify the IAM principal that made the API call",
                    "Check if the source IP is expected and authorised",
                    "Review the userData content for SSH key additions",
                    "Examine recent SSH authentication logs on the affected instance",
                    "Check for other instances modified by the same principal",
                    "Review IAM permissions of the principal for EC2 modification capabilities",
                ],
                containment_actions=[
                    "Revert the instance metadata or userData to previous state",
                    "Revoke the IAM principal's EC2 modification permissions",
                    "Terminate active SSH sessions to the affected instance",
                    "Review and remove unauthorized SSH keys from the instance",
                    "Implement SCPs to restrict ModifyInstanceAttribute actions",
                    "Enable instance metadata service v2 (IMDSv2) to prevent SSRF abuse",
                    "Review CloudTrail logs for similar modifications across the environment",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist authorised automation tools and infrastructure-as-code deployments",
            detection_coverage="90% - catches metadata-based key injection",
            evasion_considerations="Cannot evade if CloudTrail is enabled and monitoring EC2 API calls",
            implementation_effort=EffortLevel.LOW,
            implementation_time="45 minutes - 1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled", "CloudTrail logs sent to CloudWatch"],
        ),
        # Strategy 3: Suspicious Process Execution for SSH Key Modification
        DetectionStrategy(
            strategy_id="t1098004-process-monitoring",
            name="Detect SSH Key Modification via Process Monitoring",
            description=(
                "Monitor for suspicious processes or commands that modify authorized_keys files, "
                "including shell redirection, echo commands, and text editor usage."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, @message, processName, commandLine, userName, instanceId
| filter @message like /authorized_keys/
| filter processName in ["bash", "sh", "echo", "tee", "vim", "vi", "nano", "sed", "cat"]
| filter commandLine like />>|>|[|]/
| stats count() as executions by processName, userName, instanceId, bin(5m)
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect suspicious process execution modifying SSH keys

Parameters:
  CloudWatchLogGroup:
    Type: String
    Description: Log group containing process execution logs
  SNSTopicArn:
    Type: String
    Description: SNS topic for alerts

Resources:
  # Step 1: Monitor shell commands modifying authorized_keys
  ShellCommandFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudWatchLogGroup
      FilterPattern: '[time, instance, process="bash" || process="sh" || process="echo", command="*authorized_keys*"]'
      MetricTransformations:
        - MetricName: SSHKeyShellModification
          MetricNamespace: Security/T1098.004
          MetricValue: "1"

  # Step 2: Monitor text editor access to authorized_keys
  EditorAccessFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudWatchLogGroup
      FilterPattern: '[time, instance, editor="vim" || editor="vi" || editor="nano", file="*authorized_keys*"]'
      MetricTransformations:
        - MetricName: SSHKeyEditorAccess
          MetricNamespace: Security/T1098.004
          MetricValue: "1"

  # Step 3: Create alarm for suspicious modifications
  SSHKeyModificationAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1098.004-SuspiciousSSHKeyModification
      AlarmDescription: Suspicious process modifying SSH authorized_keys
      MetricName: SSHKeyShellModification
      Namespace: Security/T1098.004
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 1
      ComparisonOperator: GreaterThanOrEqualToThreshold
      AlarmActions:
        - !Ref SNSTopicArn""",
                terraform_template="""# Detect suspicious process execution modifying SSH keys

variable "cloudwatch_log_group" {
  type        = string
  description = "Log group containing process execution logs"
}

variable "alert_email" {
  type        = string
  description = "Email for alerts"
}

resource "aws_sns_topic" "alerts" {
  name = "ssh-key-process-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 1: Monitor shell commands modifying authorized_keys
resource "aws_cloudwatch_log_metric_filter" "shell_modification" {
  name           = "ssh-key-shell-modification"
  log_group_name = var.cloudwatch_log_group
  pattern        = "[time, instance, process=\"bash\" || process=\"sh\" || process=\"echo\", command=\"*authorized_keys*\"]"

  metric_transformation {
    name      = "SSHKeyShellModification"
    namespace = "Security/T1098.004"
    value     = "1"
  }
}

# Step 2: Monitor text editor access to authorized_keys
resource "aws_cloudwatch_log_metric_filter" "editor_access" {
  name           = "ssh-key-editor-access"
  log_group_name = var.cloudwatch_log_group
  pattern        = "[time, instance, editor=\"vim\" || editor=\"vi\" || editor=\"nano\", file=\"*authorized_keys*\"]"

  metric_transformation {
    name      = "SSHKeyEditorAccess"
    namespace = "Security/T1098.004"
    value     = "1"
  }
}

# Step 3: Create alarm for suspicious modifications
resource "aws_cloudwatch_metric_alarm" "ssh_key_modification" {
  alarm_name          = "T1098.004-SuspiciousSSHKeyModification"
  alarm_description   = "Suspicious process modifying SSH authorized_keys"
  metric_name         = "SSHKeyShellModification"
  namespace           = "Security/T1098.004"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="medium",
                alert_title="Suspicious SSH Key Modification Process Detected",
                alert_description_template=(
                    "Suspicious process detected modifying authorized_keys. Instance: {instance_id}. "
                    "Process: {process_name}. User: {user_name}. Command: {command_line}"
                ),
                investigation_steps=[
                    "Review the complete command line and process execution details",
                    "Identify the user account that executed the command",
                    "Check the parent process to understand how the command was initiated",
                    "Review the contents of the modified authorized_keys file",
                    "Check SSH authentication logs for logins using the newly added key",
                    "Investigate if the user account itself is compromised",
                    "Review recent commands executed by the same user",
                ],
                containment_actions=[
                    "Remove unauthorized SSH keys from authorized_keys files",
                    "Lock or disable the user account if compromised",
                    "Kill any active processes spawned by suspicious sessions",
                    "Review other files modified by the same user or process",
                    "Implement command logging and auditing for all users",
                    "Restrict shell access to authorised users only",
                    "Enable sudo logging to track privilege escalation attempts",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal SSH key management by authorised administrators and automation",
            detection_coverage="70% - catches command-line modifications",
            evasion_considerations="Attackers may use custom scripts or compile binaries to evade pattern matching",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=[
                "CloudWatch Logs Agent",
                "Process execution logging",
                "Command-line argument capture enabled",
            ],
        ),
        # Strategy 4: GCP Compute Instance SSH Key Monitoring
        DetectionStrategy(
            strategy_id="t1098004-gcp-metadata",
            name="GCP: Detect SSH Key Addition via Instance Metadata",
            description=(
                "Monitor GCP Compute Engine instance metadata modifications that add SSH keys "
                "to project or instance metadata."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gce_instance"
protoPayload.methodName="v1.compute.instances.setMetadata"
OR protoPayload.methodName="v1.compute.projects.setCommonInstanceMetadata"
protoPayload.request.metadata.items.key="ssh-keys"''',
                gcp_terraform_template="""# GCP: Detect SSH key addition via instance metadata

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for alerts"
}

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "email" {
  project      = var.project_id
  display_name = "SSH Key Modification Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log-based metric for SSH key additions
resource "google_logging_metric" "ssh_key_additions" {
  project = var.project_id
  name    = "ssh-key-metadata-modifications"
  filter  = <<-EOT
    resource.type="gce_instance"
    protoPayload.methodName="v1.compute.instances.setMetadata"
    OR protoPayload.methodName="v1.compute.projects.setCommonInstanceMetadata"
    protoPayload.request.metadata.items.key="ssh-keys"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "instance_name"
      value_type  = "STRING"
      description = "Instance where SSH key was modified"
    }
    labels {
      key         = "principal_email"
      value_type  = "STRING"
      description = "User who modified SSH keys"
    }
  }

  label_extractors = {
    instance_name   = "EXTRACT(resource.labels.instance_id)"
    principal_email = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
  }
}

# Step 3: Create alert policy
resource "google_monitoring_alert_policy" "ssh_key_modification" {
  project      = var.project_id
  display_name = "T1098.004: SSH Key Metadata Modification"
  combiner     = "OR"
  conditions {
    display_name = "SSH key added to instance metadata"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.ssh_key_additions.name}\" resource.type=\"gce_instance\""
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
    content   = "SSH key was added to GCE instance metadata. This may indicate an attempt to establish persistent access. Investigate immediately."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="high",
                alert_title="GCP: SSH Key Added to Instance Metadata",
                alert_description_template=(
                    "SSH key was added to GCE instance metadata. Instance: {instance_name}. "
                    "Principal: {principal_email}. Method: {method_name}. "
                    "This may indicate persistence establishment."
                ),
                investigation_steps=[
                    "Review the Cloud Logging entry for the complete metadata modification",
                    "Identify the principal that added the SSH key",
                    "Check if the principal's account is authorised for this action",
                    "Review the SSH key fingerprint and compare with known authorised keys",
                    "Examine recent SSH authentication logs on the instance",
                    "Check for other instances modified by the same principal",
                    "Review the principal's recent API activity across the project",
                ],
                containment_actions=[
                    "Remove the unauthorised SSH key from instance metadata",
                    "Disable or suspend the compromised principal account",
                    "Terminate active SSH sessions to the affected instance",
                    "Create a snapshot of the instance for forensic analysis",
                    "Review and restrict IAM permissions for compute.instances.setMetadata",
                    "Enable OS Login to centrally manage SSH access",
                    "Implement organisation policy constraints to restrict metadata modifications",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist authorised infrastructure-as-code tools and deployment pipelines",
            detection_coverage="95% - catches all metadata-based SSH key additions",
            evasion_considerations="Cannot evade if Cloud Audit Logs are enabled",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-1.5 hours",
            estimated_monthly_cost="$10-25",
            prerequisites=[
                "Cloud Logging API enabled",
                "Admin Activity audit logs enabled",
            ],
        ),
        # Strategy 5: SSH Authentication Success After Key Addition
        DetectionStrategy(
            strategy_id="t1098004-auth-correlation",
            name="Correlate SSH Key Addition with Subsequent Authentication",
            description=(
                "Detect SSH key additions followed by successful SSH authentication within a short time window, "
                "indicating potential unauthorized access establishment."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, @message, eventType, instanceId, userName, sourceIP
| filter @message like /authorized_keys/ or @message like /Accepted publickey/
| sort @timestamp asc
| stats earliest(@timestamp) as first_event, latest(@timestamp) as last_event,
  count(*) as events by instanceId, userName
| filter events >= 2 and (last_event - first_event) < 3600000
| sort first_event desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Correlate SSH key addition with authentication events

Parameters:
  CloudWatchLogGroup:
    Type: String
    Description: Log group containing auth and file modification logs
  SNSTopicArn:
    Type: String
    Description: SNS topic for alerts

Resources:
  # Step 1: Create metric filter for key addition
  KeyAdditionFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudWatchLogGroup
      FilterPattern: '[time, instance, msg="*authorized_keys*modified*"]'
      MetricTransformations:
        - MetricName: SSHKeyAddition
          MetricNamespace: Security/T1098.004
          MetricValue: "1"
          DefaultValue: 0

  # Step 2: Create metric filter for SSH authentication
  SSHAuthFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudWatchLogGroup
      FilterPattern: '[time, instance, msg="*Accepted publickey*"]'
      MetricTransformations:
        - MetricName: SSHPublicKeyAuth
          MetricNamespace: Security/T1098.004
          MetricValue: "1"
          DefaultValue: 0

  # Step 3: Create composite alarm for correlation
  CorrelatedAccessAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1098.004-SSHKeyAdditionAndAuth
      AlarmDescription: SSH key added and immediately used for authentication
      MetricName: SSHPublicKeyAuth
      Namespace: Security/T1098.004
      Statistic: Sum
      Period: 3600
      EvaluationPeriods: 1
      Threshold: 1
      ComparisonOperator: GreaterThanOrEqualToThreshold
      AlarmActions:
        - !Ref SNSTopicArn""",
                terraform_template="""# Correlate SSH key addition with authentication events

variable "cloudwatch_log_group" {
  type        = string
  description = "Log group containing auth and file modification logs"
}

variable "alert_email" {
  type = string
}

resource "aws_sns_topic" "alerts" {
  name = "ssh-correlation-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 1: Create metric filter for key addition
resource "aws_cloudwatch_log_metric_filter" "key_addition" {
  name           = "ssh-key-addition"
  log_group_name = var.cloudwatch_log_group
  pattern        = "[time, instance, msg=\"*authorized_keys*modified*\"]"

  metric_transformation {
    name          = "SSHKeyAddition"
    namespace     = "Security/T1098.004"
    value         = "1"
    default_value = 0
  }
}

# Step 2: Create metric filter for SSH authentication
resource "aws_cloudwatch_log_metric_filter" "ssh_auth" {
  name           = "ssh-publickey-auth"
  log_group_name = var.cloudwatch_log_group
  pattern        = "[time, instance, msg=\"*Accepted publickey*\"]"

  metric_transformation {
    name          = "SSHPublicKeyAuth"
    namespace     = "Security/T1098.004"
    value         = "1"
    default_value = 0
  }
}

# Step 3: Create alarm for correlated events
resource "aws_cloudwatch_metric_alarm" "correlated_access" {
  alarm_name          = "T1098.004-SSHKeyAdditionAndAuth"
  alarm_description   = "SSH key added and immediately used for authentication"
  metric_name         = "SSHPublicKeyAuth"
  namespace           = "Security/T1098.004"
  statistic           = "Sum"
  period              = 3600
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="critical",
                alert_title="SSH Key Added and Immediately Used for Authentication",
                alert_description_template=(
                    "SSH key was added to instance {instance_id} and used for authentication within 1 hour. "
                    "User: {user_name}. Source IP: {source_ip}. "
                    "This is a strong indicator of unauthorised persistence establishment."
                ),
                investigation_steps=[
                    "Compare timestamps of key addition and authentication events",
                    "Identify the source IP address of the SSH connection",
                    "Check if the source IP is from an expected location or VPN",
                    "Review the SSH key fingerprint used for authentication",
                    "Examine all commands executed during the SSH session",
                    "Check for file downloads or uploads during the session",
                    "Review network connections established from the instance during the session",
                    "Investigate if lateral movement occurred to other instances",
                ],
                containment_actions=[
                    "Immediately terminate the active SSH session",
                    "Remove the unauthorised SSH key from authorized_keys",
                    "Block the source IP address at the security group level",
                    "Isolate the instance from the network for forensic analysis",
                    "Review and rotate all credentials accessible from the instance",
                    "Search for and remove any additional persistence mechanisms",
                    "Conduct full forensic analysis to determine breach scope",
                    "Review logs for data exfiltration or lateral movement attempts",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Exclude authorised system provisioning and user onboarding workflows",
            detection_coverage="80% - high confidence in correlated events",
            evasion_considerations="Attackers may delay SSH authentication to avoid time-based correlation",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-2.5 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=[
                "CloudWatch Logs Agent",
                "SSH authentication logging",
                "File integrity monitoring",
                "Log aggregation from both sources",
            ],
        ),
    ],
    recommended_order=[
        "t1098004-metadata-injection",
        "t1098004-file-integrity",
        "t1098004-gcp-metadata",
        "t1098004-auth-correlation",
        "t1098004-process-monitoring",
    ],
    total_effort_hours=8.5,
    coverage_improvement="+25% improvement for Persistence tactic",
)
