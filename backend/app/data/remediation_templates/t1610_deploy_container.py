"""
T1610 - Deploy Container

Adversaries deploy containers to facilitate execution or bypass defences.
Used by TeamTNT, Kinsing, Doki, and Peirates.
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
    technique_id="T1610",
    technique_name="Deploy Container",
    tactic_ids=["TA0005", "TA0002"],  # Defense Evasion, Execution
    mitre_url="https://attack.mitre.org/techniques/T1610/",
    threat_context=ThreatContext(
        description=(
            "Adversaries deploy containers to facilitate execution or bypass defences. "
            "Deployment methods include Docker APIs, Kubernetes dashboards, and Kubeflow. "
            "In Kubernetes, attackers may deploy privileged containers to escape to the host "
            "and access other containers on the same node."
        ),
        attacker_goal="Execute malicious code and evade defences via container deployment",
        why_technique=[
            "Containers can run with privileged access",
            "Kubernetes allows node-wide access",
            "ReplicaSets/DaemonSets enable multi-node deployment",
            "Can mount host filesystems for escape",
            "Bypasses traditional security controls",
            "Malicious images can download malware at runtime",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "High risk due to privileged container capabilities, potential for host escape, "
            "and multi-node deployment via DaemonSets. Commonly used for cryptomining and persistence."
        ),
        business_impact=[
            "Unauthorised code execution",
            "Host escape and lateral movement",
            "Cryptomining resource abuse",
            "Data exfiltration",
            "Cluster-wide compromise",
        ],
        typical_attack_phase="execution",
        often_precedes=["T1496.001", "T1530", "T1552.005"],
        often_follows=["T1078.004", "T1190", "T1552.001"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1610-aws-ecs",
            name="AWS ECS Container Deployment Detection",
            description="Detect container deployments in ECS clusters, focusing on suspicious task definitions and privileged containers.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, userIdentity.principalId, requestParameters.taskDefinition
| filter eventSource = "ecs.amazonaws.com"
| filter eventName = "RunTask" or eventName = "RegisterTaskDefinition"
| filter requestParameters.containerDefinitions.0.privileged = true or requestParameters.taskDefinition like /unknown/
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect suspicious ECS container deployments

Parameters:
  CloudTrailLogGroup:
    Type: String
    Description: CloudTrail log group name
  AlertEmail:
    Type: String
    Description: Email for alerts

Resources:
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Detect container task launches
  ContainerDeploymentFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventName = "RunTask") || ($.eventName = "RegisterTaskDefinition") }'
      MetricTransformations:
        - MetricName: ContainerDeployments
          MetricNamespace: Security
          MetricValue: "1"

  ContainerDeploymentAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: SuspiciousContainerDeployment
      MetricName: ContainerDeployments
      Namespace: Security
      Statistic: Sum
      Period: 300
      Threshold: 5
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect suspicious ECS container deployments

variable "cloudtrail_log_group" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "container-deployment-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Metric filter for container deployments
resource "aws_cloudwatch_log_metric_filter" "container_deploy" {
  name           = "container-deployments"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventName = RunTask) || ($.eventName = RegisterTaskDefinition) }"

  metric_transformation {
    name      = "ContainerDeployments"
    namespace = "Security"
    value     = "1"
  }
}

# Alert on suspicious deployment activity
resource "aws_cloudwatch_metric_alarm" "container_deploy" {
  alarm_name          = "SuspiciousContainerDeployment"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ContainerDeployments"
  namespace           = "Security"
  period              = 300
  statistic           = "Sum"
  threshold           = 5
  alarm_actions       = [aws_sns_topic.alerts.arn]
  alarm_description   = "Detects suspicious container deployment activity"
}""",
                alert_severity="high",
                alert_title="Suspicious Container Deployment Detected",
                alert_description_template="Container deployment detected: {taskDefinition} by {principalId}.",
                investigation_steps=[
                    "Review task definition for privileged settings",
                    "Check container image source and reputation",
                    "Verify deployment was authorised",
                    "Review principal's recent activity",
                    "Check for host namespace mounts",
                    "Inspect container runtime parameters",
                ],
                containment_actions=[
                    "Stop unauthorised tasks immediately",
                    "Revoke excessive ECS permissions",
                    "Require task definition approval process",
                    "Enable ECS container image scanning",
                    "Implement service control policies",
                    "Review and lock down IAM roles",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known CI/CD pipelines and authorised deployment roles",
            detection_coverage="80% - catches ECS deployments",
            evasion_considerations="Attackers may use stolen authorised credentials or deploy slowly to avoid rate-based detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-15",
            prerequisites=["CloudTrail enabled", "CloudWatch Logs Insights"],
        ),
        DetectionStrategy(
            strategy_id="t1610-aws-eks",
            name="AWS EKS Kubernetes Pod Deployment Detection",
            description="Detect pod deployments in EKS, especially privileged pods and DaemonSets.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, user.username, objectRef.namespace, objectRef.name, requestObject.spec.containers.0.securityContext.privileged
| filter objectRef.resource = "pods" or objectRef.resource = "daemonsets"
| filter verb = "create"
| filter requestObject.spec.containers.0.securityContext.privileged = true or objectRef.resource = "daemonsets"
| sort @timestamp desc""",
                cloudformation_template='''AWSTemplateFormatVersion: '2010-09-09'
Description: Detect suspicious Kubernetes pod deployments in EKS

Parameters:
  EKSClusterName:
    Type: String
    Description: EKS cluster name
  AlertEmail:
    Type: String
    Description: Email for alerts

Resources:
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Query definition for suspicious pod deployments
  PodDeploymentQueryDefinition:
    Type: AWS::Logs::QueryDefinition
    Properties:
      Name: SuspiciousPodDeployments
      LogGroupNames:
        - !Sub "/aws/eks/${EKSClusterName}/cluster"
      QueryString: |
        fields @timestamp, user.username, objectRef.name, requestObject.spec.containers.0.securityContext.privileged
        | filter objectRef.resource = "pods" or objectRef.resource = "daemonsets"
        | filter verb = "create"
        | filter requestObject.spec.containers.0.securityContext.privileged = true or objectRef.resource = "daemonsets"''',
                terraform_template="""# Detect suspicious Kubernetes pod deployments

variable "eks_cluster_name" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "eks-pod-deployment-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# CloudWatch query definition for pod deployments
resource "aws_cloudwatch_query_definition" "pod_deployments" {
  name = "SuspiciousPodDeployments"

  log_group_names = [
    "/aws/eks/${var.eks_cluster_name}/cluster"
  ]

  query_string = <<-EOT
    fields @timestamp, user.username, objectRef.name, requestObject.spec.containers.0.securityContext.privileged
    | filter objectRef.resource = "pods" or objectRef.resource = "daemonsets"
    | filter verb = "create"
    | filter requestObject.spec.containers.0.securityContext.privileged = true or objectRef.resource = "daemonsets"
  EOT
}

# Metric filter for pod deployments
resource "aws_cloudwatch_log_metric_filter" "pod_deploy" {
  name           = "suspicious-pod-deployments"
  log_group_name = "/aws/eks/${var.eks_cluster_name}/cluster"
  pattern        = "{ ($.objectRef.resource = pods || $.objectRef.resource = daemonsets) && $.verb = create }"

  metric_transformation {
    name      = "SuspiciousPodDeployments"
    namespace = "Security/EKS"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "pod_deploy" {
  alarm_name          = "SuspiciousPodDeployment"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "SuspiciousPodDeployments"
  namespace           = "Security/EKS"
  period              = 300
  statistic           = "Sum"
  threshold           = 3
  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="high",
                alert_title="Suspicious Kubernetes Pod Deployment",
                alert_description_template="Pod deployment detected in namespace {namespace} by {username}.",
                investigation_steps=[
                    "Check if pod is privileged or using host namespaces",
                    "Verify pod image source (check for 'latest' tag)",
                    "Review deploying user's permissions",
                    "Check for DaemonSet deployments",
                    "Inspect pod for volume mounts to host filesystem",
                    "Review pod network policies",
                ],
                containment_actions=[
                    "Delete unauthorised pods/DaemonSets",
                    "Implement admission controllers (OPA/Kyverno)",
                    "Enforce Pod Security Standards",
                    "Require image signatures via admission webhook",
                    "Disable privileged containers via policy",
                    "Enable Kubernetes audit logging",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known operators and system namespaces (kube-system, kube-public)",
            detection_coverage="85% - catches pod and DaemonSet deployments",
            evasion_considerations="Attackers may use RoleBindings instead of ClusterRoleBindings to limit scope",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["EKS control plane logging enabled", "Audit logs enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1610-gcp-gke",
            name="GCP GKE Container Deployment Detection",
            description="Detect container/pod deployments in GKE clusters.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="k8s_cluster"
protoPayload.resourceName=~"pods|daemonsets"
protoPayload.methodName=~"create"
(protoPayload.request.spec.containers.securityContext.privileged=true
OR protoPayload.resourceName=~"daemonsets")""",
                gcp_terraform_template="""# GCP: Detect GKE container deployments

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

# Log metric for suspicious pod deployments
resource "google_logging_metric" "pod_deployment" {
  name   = "suspicious-pod-deployments"
  filter = <<-EOT
    resource.type="k8s_cluster"
    protoPayload.resourceName=~"pods|daemonsets"
    protoPayload.methodName=~"create"
    (protoPayload.request.spec.containers.securityContext.privileged=true
    OR protoPayload.resourceName=~"daemonsets")
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "namespace"
      value_type  = "STRING"
      description = "Kubernetes namespace"
    }
  }
  label_extractors = {
    "namespace" = "EXTRACT(protoPayload.resourceName)"
  }
}

# Alert policy for deployments
resource "google_monitoring_alert_policy" "pod_deployment" {
  display_name = "Suspicious GKE Pod Deployment"
  combiner     = "OR"
  conditions {
    display_name = "Pod/DaemonSet deployment detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.pod_deployment.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
  documentation {
    content   = "Suspicious pod deployment detected. Investigate namespace and deploying user."
    mime_type = "text/markdown"
  }
}

# Binary Authorization for image verification
resource "google_binary_authorization_policy" "policy" {
  admission_whitelist_patterns {
    name_pattern = "gcr.io/${var.project_id}/*"
  }
  default_admission_rule {
    evaluation_mode  = "REQUIRE_ATTESTATION"
    enforcement_mode = "ENFORCED_BLOCK_AND_AUDIT_LOG"
    require_attestations_by = []
  }
}""",
                alert_severity="high",
                alert_title="GCP: Suspicious GKE Container Deployment",
                alert_description_template="Container deployment detected in GKE cluster.",
                investigation_steps=[
                    "Check pod security context (privileged, host namespaces)",
                    "Verify container image source and tags",
                    "Review deploying service account",
                    "Check for DaemonSet deployments",
                    "Inspect volume mounts",
                    "Review RBAC permissions",
                ],
                containment_actions=[
                    "Delete unauthorised pods",
                    "Enable Binary Authorization",
                    "Implement Pod Security Policies/Standards",
                    "Use admission controllers",
                    "Require image attestations",
                    "Review service account permissions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist system namespaces and authorised service accounts",
            detection_coverage="85% - catches GKE deployments",
            evasion_considerations="Slow deployments may avoid rate-based detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$10-25",
            prerequisites=["GKE audit logging enabled", "Cloud Logging API enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1610-gcp-cloud-run",
            name="GCP Cloud Run Container Deployment Detection",
            description="Detect container deployments to Cloud Run services.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.serviceName="run.googleapis.com"
protoPayload.methodName=~"google.cloud.run.v1.Services.CreateService|google.cloud.run.v1.Services.ReplaceService"''',
                gcp_terraform_template="""# GCP: Detect Cloud Run deployments

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

# Log metric for Cloud Run deployments
resource "google_logging_metric" "cloud_run_deploy" {
  name   = "cloud-run-deployments"
  filter = <<-EOT
    protoPayload.serviceName="run.googleapis.com"
    protoPayload.methodName=~"CreateService|ReplaceService"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Alert on Cloud Run deployments
resource "google_monitoring_alert_policy" "cloud_run_deploy" {
  display_name = "Cloud Run Container Deployment"
  combiner     = "OR"
  conditions {
    display_name = "Cloud Run service deployed"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.cloud_run_deploy.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="medium",
                alert_title="GCP: Cloud Run Container Deployed",
                alert_description_template="Container service deployed to Cloud Run.",
                investigation_steps=[
                    "Verify deployment was authorised",
                    "Check container image source",
                    "Review deploying identity",
                    "Check service configuration",
                    "Review IAM permissions",
                ],
                containment_actions=[
                    "Delete unauthorised services",
                    "Require deployment approvals",
                    "Use Binary Authorization",
                    "Implement Org Policies",
                    "Review service account permissions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist CI/CD service accounts",
            detection_coverage="90% - catches Cloud Run deployments",
            evasion_considerations="Cannot easily evade",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
    ],
    recommended_order=[
        "t1610-aws-eks",
        "t1610-gcp-gke",
        "t1610-aws-ecs",
        "t1610-gcp-cloud-run",
    ],
    total_effort_hours=6.0,
    coverage_improvement="+18% improvement for Defense Evasion and Execution tactics",
)
