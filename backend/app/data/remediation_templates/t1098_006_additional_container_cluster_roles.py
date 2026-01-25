"""
T1098.006 - Account Manipulation: Additional Container Cluster Roles

Adversaries add extra roles or permissions to compromised user or service accounts
within container orchestration systems to maintain persistent access.
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
    technique_id="T1098.006",
    technique_name="Account Manipulation: Additional Container Cluster Roles",
    tactic_ids=["TA0003", "TA0004"],
    mitre_url="https://attack.mitre.org/techniques/T1098/006/",
    threat_context=ThreatContext(
        description=(
            "Adversaries add additional roles or permissions to compromised user or "
            "service accounts within container orchestration systems (Kubernetes, EKS, GKE) "
            "to maintain persistent access. This involves creating RoleBinding or "
            "ClusterRoleBinding objects to associate elevated roles with compromised accounts, "
            "or modifying ABAC policies to grant additional permissions."
        ),
        attacker_goal="Maintain persistent privileged access to container clusters via role manipulation",
        why_technique=[
            "Provides persistent cluster access",
            "Enables privilege escalation",
            "Difficult to detect without audit logging",
            "Can grant cluster-admin privileges",
            "Works across cloud-native RBAC systems",
        ],
        known_threat_actors=[],
        recent_campaigns=[],
        prevalence="uncommon",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "High-impact technique enabling persistent privileged access to container "
            "clusters. Successful exploitation can lead to cluster-wide compromise and "
            "data exfiltration. Particularly dangerous in cloud environments with integrated "
            "IAM systems."
        ),
        business_impact=[
            "Persistent cluster access",
            "Privilege escalation risk",
            "Unauthorised workload deployment",
            "Sensitive data access",
            "Compliance violations",
        ],
        typical_attack_phase="persistence",
        often_precedes=["T1078.004", "T1610", "T1613"],
        often_follows=["T1078", "T1552.007"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1098-006-aws-eks-rbac",
            name="AWS EKS RBAC Modification Detection",
            description="Detect suspicious RoleBinding or ClusterRoleBinding creation in EKS clusters.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, user.username, objectRef.name, objectRef.namespace, verb, responseStatus.code
| filter kubernetes.audit.k8s.io/v1
| filter objectRef.resource = "rolebindings" or objectRef.resource = "clusterrolebindings"
| filter verb = "create" or verb = "update" or verb = "patch"
| filter responseStatus.code = 201 or responseStatus.code = 200
| filter user.username != "system:serviceaccount:kube-system:*"
| stats count(*) as modifications by user.username, objectRef.resource, bin(5m)
| filter modifications > 0
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect RBAC modifications in EKS clusters

Parameters:
  EKSAuditLogGroup:
    Type: String
    Description: CloudWatch log group for EKS audit logs
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: EKS RBAC Modification Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  RBACModificationFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref EKSAuditLogGroup
      FilterPattern: '{ ($.objectRef.resource = "rolebindings" || $.objectRef.resource = "clusterrolebindings") && ($.verb = "create" || $.verb = "update" || $.verb = "patch") && $.responseStatus.code = 201 }'
      MetricTransformations:
        - MetricName: EKSRBACModifications
          MetricNamespace: Security/EKS
          MetricValue: "1"

  RBACModificationAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: EKS-Suspicious-RBAC-Modification
      AlarmDescription: Detects suspicious RBAC binding modifications in EKS
      MetricName: EKSRBACModifications
      Namespace: Security/EKS
      Statistic: Sum
      Period: 300
      Threshold: 5
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref AlertTopic]
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Sid: AllowCloudWatchPublish
            Effect: Allow
            Principal:
              Service: cloudwatch.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId""",
                terraform_template="""# Detect RBAC modifications in EKS clusters

variable "eks_audit_log_group" {
  type        = string
  description = "CloudWatch log group for EKS audit logs"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

variable "location" {
  type        = string
  description = "Azure region for resources"
  default     = "uksouth"
}

resource "aws_sns_topic" "eks_rbac_alerts" {
  name         = "eks-rbac-modification-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "EKS RBAC Modification Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.eks_rbac_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "rbac_modifications" {
  name           = "eks-rbac-modifications"
  log_group_name = var.eks_audit_log_group
  pattern        = "{ ($.objectRef.resource = \"rolebindings\" || $.objectRef.resource = \"clusterrolebindings\") && ($.verb = \"create\" || $.verb = \"update\" || $.verb = \"patch\") && $.responseStatus.code = 201 }"

  metric_transformation {
    name      = "EKSRBACModifications"
    namespace = "Security/EKS"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "rbac_modification_alert" {
  alarm_name          = "EKS-Suspicious-RBAC-Modification"
  alarm_description   = "Detects suspicious RBAC binding modifications in EKS"
  metric_name         = "EKSRBACModifications"
  namespace           = "Security/EKS"
  statistic           = "Sum"
  period              = 300
  threshold           = 5
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.eks_rbac_alerts.arn]
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.eks_rbac_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchPublish"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.eks_rbac_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="Suspicious EKS RBAC Modification Detected",
                alert_description_template="Suspicious RoleBinding/ClusterRoleBinding modification by {username} in namespace {namespace}.",
                investigation_steps=[
                    "Review the user or service account that created the binding",
                    "Check if the role assignment is from a known IP address",
                    "Verify the role being assigned (e.g., cluster-admin)",
                    "Check for other suspicious activities from the same account",
                    "Review EKS audit logs for authentication source",
                ],
                containment_actions=[
                    "Delete unauthorised RoleBindings/ClusterRoleBindings",
                    "Revoke credentials for compromised service accounts",
                    "Review and restrict RBAC create/update permissions",
                    "Enable MFA for cluster access",
                    "Rotate cluster credentials if compromise confirmed",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude known CI/CD service accounts and automation tools from alerts",
            detection_coverage="80% - catches most RBAC modifications when audit logging enabled",
            evasion_considerations="Attackers may use legitimate automation accounts or disable audit logging",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$10-25",
            prerequisites=["EKS control plane logging enabled for audit logs"],
        ),
        DetectionStrategy(
            strategy_id="t1098-006-aws-eks-clusteradmin",
            name="AWS EKS Cluster-Admin Role Assignment Detection",
            description="Detect assignment of cluster-admin or high-privilege roles to accounts.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, user.username, requestObject.roleRef.name, objectRef.name, objectRef.namespace
| filter kubernetes.audit.k8s.io/v1
| filter objectRef.resource = "clusterrolebindings"
| filter verb = "create"
| filter requestObject.roleRef.name like /cluster-admin|admin|edit|system:/
| filter user.username != "system:masters"
| sort @timestamp desc""",
                terraform_template="""# Detect cluster-admin role assignments in EKS

variable "eks_audit_log_group" {
  type        = string
  description = "CloudWatch log group for EKS audit logs"
}

variable "alert_email" {
  type        = string
  description = "Email for critical security alerts"
}

variable "location" {
  type        = string
  description = "Azure region for resources"
  default     = "uksouth"
}

resource "aws_sns_topic" "cluster_admin_alerts" {
  name         = "eks-cluster-admin-assignment-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "EKS Cluster Admin Assignment Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.cluster_admin_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "cluster_admin_assignments" {
  name           = "eks-cluster-admin-assignments"
  log_group_name = var.eks_audit_log_group
  pattern        = "{ $.objectRef.resource = \"clusterrolebindings\" && $.verb = \"create\" && $.requestObject.roleRef.name = \"cluster-admin\" }"

  metric_transformation {
    name      = "EKSClusterAdminAssignments"
    namespace = "Security/EKS"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "cluster_admin_alert" {
  alarm_name          = "EKS-Cluster-Admin-Assignment"
  alarm_description   = "Critical: Cluster-admin role assigned in EKS cluster"
  metric_name         = "EKSClusterAdminAssignments"
  namespace           = "Security/EKS"
  statistic           = "Sum"
  period              = 60
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.cluster_admin_alerts.arn]
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.cluster_admin_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchPublish"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.cluster_admin_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}""",
                alert_severity="critical",
                alert_title="Critical: Cluster-Admin Role Assigned in EKS",
                alert_description_template="Cluster-admin role assigned to {subject} by {username}.",
                investigation_steps=[
                    "Immediately identify who/what received cluster-admin",
                    "Verify if assignment was authorised and expected",
                    "Check source IP and authentication method",
                    "Review all recent actions by the assigned account",
                    "Audit recent cluster changes for other persistence mechanisms",
                ],
                containment_actions=[
                    "Immediately delete unauthorised ClusterRoleBinding",
                    "Suspend the assigned user or service account",
                    "Rotate cluster credentials and API tokens",
                    "Review all cluster resources for tampering",
                    "Implement RBAC approval workflow",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Cluster-admin assignments should be rare and pre-authorised",
            detection_coverage="90% - very specific detection with high confidence",
            evasion_considerations="Attackers may use slightly lower privilege roles to avoid detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-15",
            prerequisites=["EKS control plane logging enabled for audit logs"],
        ),
        DetectionStrategy(
            strategy_id="t1098-006-gcp-gke-rbac",
            name="GCP GKE RBAC Modification Detection",
            description="Detect suspicious RoleBinding or ClusterRoleBinding creation in GKE clusters.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="k8s_cluster"
protoPayload.methodName=~"io.k8s.authorization.rbac.v1.*.(cluster)?rolebindings.(create|update|patch)"
protoPayload.response.code=201 OR protoPayload.response.code=200
NOT protoPayload.authenticationInfo.principalEmail=~"system:serviceaccount:kube-system:.*"''',
                gcp_terraform_template="""# GCP: Detect RBAC modifications in GKE clusters

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

variable "location" {
  type        = string
  description = "Azure region for resources"
  default     = "uksouth"
}

resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "GKE RBAC Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

resource "google_logging_metric" "gke_rbac_modifications" {
  project = var.project_id
  name    = "gke-rbac-modifications"
  filter  = <<-EOT
    resource.type="k8s_cluster"
    protoPayload.methodName=~"io.k8s.authorization.rbac.v1.*.(cluster)?rolebindings.(create|update|patch)"
    protoPayload.response.code=201 OR protoPayload.response.code=200
    NOT protoPayload.authenticationInfo.principalEmail=~"system:serviceaccount:kube-system:.*"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "gke_rbac_alert" {
  project      = var.project_id
  display_name = "GKE Suspicious RBAC Modification"
  combiner     = "OR"
  conditions {
    display_name = "RBAC binding modifications detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.gke_rbac_modifications.name}\" AND resource.type=\"k8s_cluster\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 5
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }
  notification_channels = [google_monitoring_notification_channel.email_s1.id]
  alert_strategy {
    auto_close = "604800s"
    notification_rate_limit {
      period = "300s"
    }
  }
}""",
                alert_severity="high",
                alert_title="GCP: Suspicious GKE RBAC Modification",
                alert_description_template="Suspicious RoleBinding/ClusterRoleBinding modification in GKE cluster.",
                investigation_steps=[
                    "Review the principal email that created the binding",
                    "Check if the modification originated from expected CI/CD pipelines",
                    "Verify the role being assigned and its permissions",
                    "Check GKE audit logs for authentication source and IP",
                    "Review subject (user/serviceAccount) receiving permissions",
                ],
                containment_actions=[
                    "Delete unauthorised RoleBindings/ClusterRoleBindings",
                    "Revoke compromised service account credentials",
                    "Review IAM permissions for cluster access",
                    "Enable Binary Authorisation for workload validation",
                    "Implement RBAC change approval workflow",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude known automation service accounts and approved deployment pipelines",
            detection_coverage="80% - catches most RBAC modifications when audit logging enabled",
            evasion_considerations="Attackers may use compromised automation accounts or disable audit logging",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$10-25",
            prerequisites=["GKE audit logging enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1098-006-gcp-gke-clusteradmin",
            name="GCP GKE Cluster-Admin Role Assignment Detection",
            description="Detect assignment of cluster-admin or high-privilege roles in GKE.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="k8s_cluster"
protoPayload.methodName="io.k8s.authorization.rbac.v1.clusterrolebindings.create"
protoPayload.request.roleRef.name="cluster-admin"
protoPayload.response.code=201""",
                gcp_terraform_template="""# GCP: Detect cluster-admin role assignments in GKE

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for critical security alerts"
}

variable "location" {
  type        = string
  description = "Azure region for resources"
  default     = "uksouth"
}

resource "google_monitoring_notification_channel" "email_s2" {
  project      = var.project_id
  display_name = "GKE Cluster Admin Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

resource "google_logging_metric" "cluster_admin_assignments" {
  project = var.project_id
  name    = "gke-cluster-admin-assignments"
  filter  = <<-EOT
    resource.type="k8s_cluster"
    protoPayload.methodName="io.k8s.authorization.rbac.v1.clusterrolebindings.create"
    protoPayload.request.roleRef.name="cluster-admin"
    protoPayload.response.code=201
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "cluster_admin_alert" {
  project      = var.project_id
  display_name = "GKE Cluster-Admin Assignment (Critical)"
  combiner     = "OR"
  conditions {
    display_name = "Cluster-admin role assigned"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.cluster_admin_assignments.name}\" AND resource.type=\"k8s_cluster\""
      duration        = "60s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }
  notification_channels = [google_monitoring_notification_channel.email_s2.id]
  alert_strategy {
    auto_close = "604800s"
    notification_rate_limit {
      period = "300s"
    }
  }
}""",
                alert_severity="critical",
                alert_title="GCP: Critical - Cluster-Admin Role Assigned in GKE",
                alert_description_template="Cluster-admin role assigned in GKE cluster - immediate investigation required.",
                investigation_steps=[
                    "Immediately identify the principal that assigned cluster-admin",
                    "Identify the subject (user/serviceAccount) that received privileges",
                    "Verify if assignment was authorised through change control",
                    "Check source IP and authentication method from audit logs",
                    "Review all recent cluster modifications and deployments",
                ],
                containment_actions=[
                    "Immediately delete unauthorised ClusterRoleBinding",
                    "Disable the assigned service account or user",
                    "Rotate cluster credentials and service account keys",
                    "Review all cluster workloads for malicious containers",
                    "Enable Binary Authorisation and implement RBAC approval workflow",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Cluster-admin assignments should be extremely rare and pre-approved",
            detection_coverage="95% - highly specific detection with very high confidence",
            evasion_considerations="Attackers may assign slightly lower privilege roles to avoid triggering alerts",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-15",
            prerequisites=["GKE audit logging enabled"],
        ),
        # Azure Strategy: Account Manipulation: Additional Container Cluster Roles
        DetectionStrategy(
            strategy_id="t1098006-azure",
            name="Azure Account Manipulation: Additional Container Cluster Roles Detection",
            description=(
                "Azure detection for Account Manipulation: Additional Container Cluster Roles. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.DEFENDER_ALERT,
            aws_service="n/a",
            azure_service="defender",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                defender_alert_types=[
                    "Suspicious Kubernetes service account operation detected",
                    "Privileged container detected",
                    "Role binding to the cluster-admin role detected",
                ],
                azure_terraform_template="""# Microsoft Defender for Cloud Detection
# Account Manipulation: Additional Container Cluster Roles (T1098.006)
# Microsoft Defender detects Account Manipulation: Additional Container Cluster Roles activity

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

variable "location" {
  type        = string
  description = "Azure region for resources"
  default     = "uksouth"
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
  name                = "defender-t1098-006-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "DefAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Log Analytics query for Defender alerts
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "defender_detection" {
  name                = "defender-t1098-006"
  resource_group_name = var.resource_group_name
  location            = var.location

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

                    "Suspicious Kubernetes service account operation detected",
                    "Privileged container detected",
                    "Role binding to the cluster-admin role detected"
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

  description = "Microsoft Defender detects Account Manipulation: Additional Container Cluster Roles activity"
  display_name = "Defender: Account Manipulation: Additional Container Cluster Roles"
  enabled      = true

  tags = {
    "mitre-technique" = "T1098.006"
    "detection-type"  = "security"
  }
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.defender_detection.id
}""",
                alert_severity="high",
                alert_title="Azure: Account Manipulation: Additional Container Cluster Roles Detected",
                alert_description_template=(
                    "Account Manipulation: Additional Container Cluster Roles activity detected. "
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
        "t1098-006-aws-eks-clusteradmin",
        "t1098-006-gcp-gke-clusteradmin",
        "t1098-006-aws-eks-rbac",
        "t1098-006-gcp-gke-rbac",
    ],
    total_effort_hours=8.0,
    coverage_improvement="+25% improvement for Persistence and Privilege Escalation tactics in container environments",
)
