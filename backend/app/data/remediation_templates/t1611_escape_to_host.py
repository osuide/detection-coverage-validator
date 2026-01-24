"""
T1611 - Escape to Host

Adversaries break out of containerised or virtualised environments to access
the underlying host system. Common methods include privileged containers,
bind mounts, docker.sock exploitation, and syscall abuse.

MITRE ATT&CK Reference: https://attack.mitre.org/techniques/T1611/
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
    technique_id="T1611",
    technique_name="Escape to Host",
    tactic_ids=["TA0004"],  # Privilege Escalation
    mitre_url="https://attack.mitre.org/techniques/T1611/",
    threat_context=ThreatContext(
        description=(
            "Adversaries break out of containerised or virtualised environments to gain "
            "access to the underlying host system. Common escape methods include mounting "
            "the host filesystem via bind mounts, running privileged containers, exploiting "
            "the Docker socket (docker.sock), abusing syscalls (unshare, keyctl), and "
            "leveraging hypervisor vulnerabilities."
        ),
        attacker_goal="Escape container/VM isolation to access the underlying host system",
        why_technique=[
            "Access other containers and VMs on the host",
            "Execute commands with host-level privileges",
            "Deploy persistent malware on the host",
            "Steal secrets and credentials from host",
            "Pivot to other systems via host network",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="moderate",
        trend="increasing",
        severity_score=9,
        severity_reasoning=(
            "Container escape grants host-level access, completely bypassing isolation. "
            "Attackers gain full control of the host, all containers, and can access "
            "sensitive credentials, deploy persistent malware, and pivot to other systems. "
            "This represents a complete security boundary violation."
        ),
        business_impact=[
            "Complete host system compromise",
            "Access to all containers on the host",
            "Credential and secret theft",
            "Persistent malware deployment",
            "Lateral movement to other hosts",
        ],
        typical_attack_phase="privilege_escalation",
        often_precedes=["T1078.004", "T1552.001", "T1021.007"],
        often_follows=["T1525", "T1204.003", "T1648"],
    ),
    detection_strategies=[
        # Strategy 1: AWS - Privileged Container Detection
        DetectionStrategy(
            strategy_id="t1611-aws-privileged",
            name="Privileged Container and Bind Mount Detection",
            description="Detect privileged containers and suspicious bind mounts in ECS/EKS.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, requestParameters.taskDefinition, requestParameters.containerDefinitions
| filter eventSource = "ecs.amazonaws.com"
| filter eventName = "RegisterTaskDefinition"
| filter requestParameters.containerDefinitions.0.privileged = true
   or requestParameters.containerDefinitions.0.mountPoints.0.sourceVolume = "/"
   or requestParameters.containerDefinitions.0.mountPoints.0.sourceVolume = "/var/run/docker.sock"
| fields @timestamp, userIdentity.arn, requestParameters.family, requestParameters.containerDefinitions.0.privileged, requestParameters.containerDefinitions.0.mountPoints""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect privileged containers and risky bind mounts

Parameters:
  CloudTrailLogGroup:
    Type: String
  AlertEmail:
    Type: String

Resources:
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  PrivilegedContainerFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventSource = "ecs.amazonaws.com" && $.eventName = "RegisterTaskDefinition" && ($.requestParameters.containerDefinitions[0].privileged = true || $.requestParameters.containerDefinitions[0].mountPoints[0].sourceVolume = "/" || $.requestParameters.containerDefinitions[0].mountPoints[0].sourceVolume = "/var/run/docker.sock") }'
      MetricTransformations:
        - MetricName: PrivilegedContainerCreation
          MetricNamespace: Security
          MetricValue: "1"

  PrivilegedContainerAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: PrivilegedContainerDetected
      MetricName: PrivilegedContainerCreation
      Namespace: Security
      Statistic: Sum
      Period: 300
      Threshold: 1
      ComparisonOperator: GreaterThanOrEqualToThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect privileged containers and risky bind mounts

variable "cloudtrail_log_group" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "privileged-container-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "privileged_container" {
  name           = "privileged-container-creation"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventSource = \"ecs.amazonaws.com\" && $.eventName = \"RegisterTaskDefinition\" && ($.requestParameters.containerDefinitions[0].privileged = true || $.requestParameters.containerDefinitions[0].mountPoints[0].sourceVolume = \"/\" || $.requestParameters.containerDefinitions[0].mountPoints[0].sourceVolume = \"/var/run/docker.sock\") }"

  metric_transformation {
    name      = "PrivilegedContainerCreation"
    namespace = "Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "privileged_container" {
  alarm_name          = "PrivilegedContainerDetected"
  metric_name         = "PrivilegedContainerCreation"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="critical",
                alert_title="Privileged Container or Risky Bind Mount Detected",
                alert_description_template="Privileged container or risky bind mount created in task definition {taskDefinition} by {userIdentity.arn}.",
                investigation_steps=[
                    "Identify who registered the task definition",
                    "Review container configuration for privileged flag",
                    "Check bind mounts for host filesystem access",
                    "Verify if docker.sock is mounted",
                    "Review container image source and integrity",
                    "Check for container runtime activity on host",
                ],
                containment_actions=[
                    "Stop and delete unauthorised tasks",
                    "Revoke task registration permissions",
                    "Implement SCPs to prevent privileged containers",
                    "Enable GuardDuty runtime monitoring",
                    "Audit all task definitions for privileged settings",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist legitimate system containers requiring privileged access",
            detection_coverage="90% - catches privileged containers and bind mounts",
            evasion_considerations="Cannot evade if CloudTrail is enabled; may use service roles",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled with ECS data events"],
        ),
        # Strategy 2: AWS - Container Runtime Security
        DetectionStrategy(
            strategy_id="t1611-aws-runtime",
            name="Container Runtime Escape Detection (GuardDuty)",
            description="Detect container escape attempts using GuardDuty Runtime Monitoring.",
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "PrivilegeEscalation:Runtime/DockerSocketAccessed",
                    "PrivilegeEscalation:Runtime/RuncContainerEscape",
                    "Execution:Runtime/NewBinaryExecuted",
                    "PrivilegeEscalation:Runtime/ContainerMountsHostDirectory",
                ],
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: GuardDuty container escape detection via EventBridge

Parameters:
  AlertEmail:
    Type: String

Resources:
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  ContainerEscapeRule:
    Type: AWS::Events::Rule
    Properties:
      # Scoped to specific container escape finding types to avoid alert fatigue
      EventPattern:
        source: [aws.guardduty]
        detail-type: [GuardDuty Finding]
        detail:
          type:
            # Container escape specific findings
            - "PrivilegeEscalation:Runtime/RuncContainerEscape"
            - "PrivilegeEscalation:Runtime/CGroupsReleaseAgentModified"
            - "PrivilegeEscalation:Runtime/ContainerMountsHostDirectory"
            - "PrivilegeEscalation:Runtime/DockerSocketAccessed"
            - "Execution:Runtime/NewBinaryExecuted"
          severity:
            - numeric:
                - ">="
                - 4
      Targets:
        - Id: Alert
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
            Resource: !Ref AlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn: !GetAtt ContainerEscapeRule.Arn""",
                terraform_template="""# GuardDuty container escape detection

variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "container-escape-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Dead Letter Queue for EventBridge targets
resource "aws_sqs_queue" "events_dlq" {
  name                      = "container-escape-dlq"
  message_retention_seconds = 1209600
}

resource "aws_sqs_queue_policy" "events_dlq" {
  queue_url = aws_sqs_queue.events_dlq.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "events.amazonaws.com"
      }
      Action   = "sqs:SendMessage"
      Resource = aws_sqs_queue.events_dlq.arn
    }]
  })
}

resource "aws_cloudwatch_event_rule" "container_escape" {
  name = "guardduty-container-escape"
  # Scoped to specific container escape finding types to avoid alert fatigue
  event_pattern = jsonencode({
    source        = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    detail = {
      type = [
        # Container escape specific findings
        "PrivilegeEscalation:Runtime/RuncContainerEscape",
        "PrivilegeEscalation:Runtime/CGroupsReleaseAgentModified",
        "PrivilegeEscalation:Runtime/ContainerMountsHostDirectory",
        "PrivilegeEscalation:Runtime/DockerSocketAccessed",
        "Execution:Runtime/NewBinaryExecuted"
      ]
      # Severity >= 4 (MEDIUM or above) to filter noise
      severity = [{ numeric = [">=", 4] }]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.container_escape.name
target_id = "SendToSNS"
  arn  = aws_sns_topic.alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.events_dlq.arn
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
          "aws:SourceArn" = aws_cloudwatch_event_rule.container_escape.arn
        }
      }
    }]
  })
}""",
                alert_severity="critical",
                alert_title="Container Escape Attempt Detected",
                alert_description_template="GuardDuty detected container escape behaviour: {detail.type}.",
                investigation_steps=[
                    "Review GuardDuty finding details",
                    "Identify affected container and task",
                    "Check container image provenance",
                    "Review syscalls and process tree",
                    "Investigate host-level activity",
                    "Check for lateral movement",
                ],
                containment_actions=[
                    "Immediately stop affected tasks",
                    "Isolate affected host instances",
                    "Review and rotate credentials",
                    "Scan container images for malware",
                    "Implement runtime security policies",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Minimal tuning needed; GuardDuty has built-in ML",
            detection_coverage="95% - detects runtime escape attempts",
            evasion_considerations="Difficult to evade GuardDuty runtime monitoring",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$15-30 (GuardDuty EKS/ECS runtime monitoring)",
            prerequisites=["GuardDuty enabled with EKS/ECS runtime monitoring"],
        ),
        # Strategy 3: GCP - Privileged Container Detection
        DetectionStrategy(
            strategy_id="t1611-gcp-privileged",
            name="GCP Privileged Container Detection",
            description="Detect privileged containers and host mounts in GKE.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="k8s_cluster"
protoPayload.request.spec.containers.securityContext.privileged=true
OR protoPayload.request.spec.volumes.hostPath.path="/"
OR protoPayload.request.spec.volumes.hostPath.path="/var/run/docker.sock"''',
                gcp_terraform_template="""# GCP: Detect privileged containers and host mounts

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "privileged_container" {
  project = var.project_id
  name   = "privileged-container-creation"
  filter = <<-EOT
    resource.type="k8s_cluster"
    (protoPayload.request.spec.containers.securityContext.privileged=true
    OR protoPayload.request.spec.volumes.hostPath.path="/"
    OR protoPayload.request.spec.volumes.hostPath.path="/var/run/docker.sock")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "privileged_container" {
  project      = var.project_id
  display_name = "Privileged Container Detected"
  combiner     = "OR"

  conditions {
    display_name = "Privileged container creation"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.privileged_container.name}\""
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
                alert_severity="critical",
                alert_title="GCP: Privileged Container Detected",
                alert_description_template="Privileged container or risky host mount detected in GKE cluster.",
                investigation_steps=[
                    "Identify the pod and namespace",
                    "Review pod security context settings",
                    "Check volume mounts for host filesystem",
                    "Verify pod creator and RBAC permissions",
                    "Review container image source",
                    "Check for runtime escape activity",
                ],
                containment_actions=[
                    "Delete unauthorised pods immediately",
                    "Enforce Pod Security Standards/Policies",
                    "Review RBAC permissions",
                    "Enable GKE Binary Authorisation",
                    "Implement Workload Identity",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist system DaemonSets requiring privileged access",
            detection_coverage="90% - catches privileged pods and host mounts",
            evasion_considerations="Cannot evade if audit logs are enabled",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-15",
            prerequisites=["GKE audit logging enabled", "Cloud Audit Logs enabled"],
        ),
        # Strategy 4: GCP - Runtime Security with Security Command Center
        DetectionStrategy(
            strategy_id="t1611-gcp-scc",
            name="GKE Runtime Security Monitoring",
            description="Detect container escape attempts using Security Command Center.",
            detection_type=DetectionType.SECURITY_COMMAND_CENTER,
            aws_service="n/a",
            gcp_service="security_command_center",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                scc_finding_categories=[
                    "Persistence: Launch Suspicious Process",
                    "Privilege Escalation: Anomalous Multistep Privilege Escalation",
                    "Execution: Suspicious Process",
                ],
                gcp_terraform_template="""# GCP: Security Command Center container escape detection

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email_s2" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_pubsub_topic" "scc_findings" {
  name = "scc-container-escape-findings"
}

resource "google_pubsub_subscription" "scc_findings" {
  name  = "scc-container-escape-sub"
  topic = google_pubsub_topic.scc_findings.name
}

resource "google_scc_notification_config" "container_escape" {
  config_id    = "container-escape-notifications"
  organization = var.project_id
  pubsub_topic = google_pubsub_topic.scc_findings.id

  streaming_config {
    filter = <<-EOT
      category="Persistence: Launch Suspicious Process"
      OR category="Privilege Escalation: Anomalous Multistep Privilege Escalation"
      OR category="Execution: Suspicious Process"
    EOT
  }
}""",
                alert_severity="critical",
                alert_title="GCP: Container Escape Activity Detected",
                alert_description_template="Security Command Center detected suspicious container activity indicating escape attempt.",
                investigation_steps=[
                    "Review SCC finding details and evidence",
                    "Identify affected workload and cluster",
                    "Analyse process tree and syscalls",
                    "Check for privilege escalation chains",
                    "Review container image and vulnerabilities",
                    "Investigate lateral movement",
                ],
                containment_actions=[
                    "Terminate affected pods immediately",
                    "Isolate compromised nodes",
                    "Rotate service account keys",
                    "Implement runtime security policies",
                    "Enable GKE Sandbox (gVisor)",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Minimal tuning; SCC uses threat intelligence",
            detection_coverage="95% - detects runtime escape attempts",
            evasion_considerations="Difficult to evade SCC runtime detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1.5 hours",
            estimated_monthly_cost="$20-40 (Security Command Center Premium)",
            prerequisites=[
                "Security Command Center Premium",
                "GKE Security Posture enabled",
            ],
        ),
        # Azure Strategy: Escape to Host
        DetectionStrategy(
            strategy_id="t1611-azure",
            name="Azure Escape to Host Detection",
            description=(
                "Azure detection for Escape to Host. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.DEFENDER_ALERT,
            aws_service="n/a",
            azure_service="defender",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                azure_kql_query="""// Azure Log Analytics KQL Query: Escape to Host
// MITRE ATT&CK: T1611
// Detects container escape attempts in Azure Kubernetes Service
let lookback = 24h;
// Privileged container creation in AKS
let privilegedContainers = AzureDiagnostics
| where TimeGenerated > ago(lookback)
| where ResourceType == "MANAGEDCLUSTERS"
| where Category in ("kube-audit", "kube-audit-admin")
| where log_s has "securityContext" and log_s has "privileged"
| extend AuditLog = parse_json(log_s)
| where AuditLog.verb == "create"
| project TimeGenerated, Resource, ResourceGroup,
    User = AuditLog.user.username,
    Namespace = AuditLog.objectRef.namespace,
    PodName = AuditLog.objectRef.name,
    RequestObject = AuditLog.requestObject
| extend TechniqueDetail = "Privileged container creation";
// Host path volume mounts (potential escape vector)
let hostPathMounts = AzureDiagnostics
| where TimeGenerated > ago(lookback)
| where ResourceType == "MANAGEDCLUSTERS"
| where Category in ("kube-audit", "kube-audit-admin")
| where log_s has "hostPath"
| extend AuditLog = parse_json(log_s)
| where AuditLog.verb in ("create", "update", "patch")
| project TimeGenerated, Resource, ResourceGroup,
    User = AuditLog.user.username,
    Namespace = AuditLog.objectRef.namespace,
    PodName = AuditLog.objectRef.name
| extend TechniqueDetail = "HostPath volume mount";
// Host network/PID namespace access
let hostNamespace = AzureDiagnostics
| where TimeGenerated > ago(lookback)
| where ResourceType == "MANAGEDCLUSTERS"
| where Category in ("kube-audit", "kube-audit-admin")
| where log_s has_any ("hostNetwork", "hostPID", "hostIPC")
| extend AuditLog = parse_json(log_s)
| where AuditLog.verb in ("create", "update")
| project TimeGenerated, Resource, ResourceGroup,
    User = AuditLog.user.username,
    Namespace = AuditLog.objectRef.namespace
| extend TechniqueDetail = "Host namespace access";
// Defender for Containers escape alerts
let escapeAlerts = SecurityAlert
| where TimeGenerated > ago(lookback)
| where ProductName in ("Azure Security Center", "Microsoft Defender for Cloud", "Microsoft Defender for Containers")
| where AlertName has_any (
    "container escape", "Privileged container",
    "Host volume mount", "Container with sensitive mount",
    "Suspicious container", "Container breakout"
)
| project TimeGenerated, AlertName, AlertSeverity, Description,
    CompromisedEntity, RemediationSteps
| extend TechniqueDetail = "Defender escape alert";
// Suspicious exec into container
let containerExec = AzureDiagnostics
| where TimeGenerated > ago(lookback)
| where ResourceType == "MANAGEDCLUSTERS"
| where Category in ("kube-audit", "kube-audit-admin")
| where log_s has "exec" and log_s has "pods"
| extend AuditLog = parse_json(log_s)
| where AuditLog.verb == "create"
| project TimeGenerated, Resource, ResourceGroup,
    User = AuditLog.user.username,
    Namespace = AuditLog.objectRef.namespace,
    PodName = AuditLog.objectRef.name,
    Command = AuditLog.requestObject
| extend TechniqueDetail = "Container exec";
// CAP_SYS_ADMIN or other dangerous capabilities
let dangerousCaps = AzureDiagnostics
| where TimeGenerated > ago(lookback)
| where ResourceType == "MANAGEDCLUSTERS"
| where Category in ("kube-audit", "kube-audit-admin")
| where log_s has_any ("CAP_SYS_ADMIN", "CAP_NET_ADMIN", "CAP_SYS_PTRACE")
| extend AuditLog = parse_json(log_s)
| where AuditLog.verb in ("create", "update")
| project TimeGenerated, Resource, ResourceGroup,
    User = AuditLog.user.username,
    Namespace = AuditLog.objectRef.namespace
| extend TechniqueDetail = "Dangerous capability requested";
// Union results
union privilegedContainers, hostPathMounts, hostNamespace, escapeAlerts, containerExec, dangerousCaps
| summarize
    EventCount = count(),
    TechniquesUsed = make_set(TechniqueDetail),
    Users = make_set(User, 10),
    Namespaces = make_set(Namespace, 10)
    by bin(TimeGenerated, 1h)""",
                defender_alert_types=[
                    "Suspicious activity detected",
                    "Privileged container detected",
                    "Container with sensitive mount detected",
                    "Container escape attempt",
                    "Suspicious container behavior",
                ],
                azure_terraform_template="""# Microsoft Defender for Cloud Detection
# Escape to Host (T1611)
# Microsoft Defender detects Escape to Host activity

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
  name                = "defender-t1611-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "DefAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Log Analytics query for Defender alerts
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "defender_detection" {
  name                = "defender-t1611"
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

  description = "Microsoft Defender detects Escape to Host activity"
  display_name = "Defender: Escape to Host"
  enabled      = true
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.defender_detection.id
}""",
                alert_severity="high",
                alert_title="Azure: Escape to Host Detected",
                alert_description_template=(
                    "Escape to Host activity detected. "
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
        "t1611-aws-runtime",
        "t1611-aws-privileged",
        "t1611-gcp-scc",
        "t1611-gcp-privileged",
    ],
    total_effort_hours=4.0,
    coverage_improvement="+25% improvement for Privilege Escalation tactic",
)
