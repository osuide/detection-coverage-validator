"""
T1613 - Container and Resource Discovery

Adversaries discover containers, pods, images, deployments, and cluster resources
via Docker/Kubernetes APIs and dashboards to inform lateral movement and execution.
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
    technique_id="T1613",
    technique_name="Container and Resource Discovery",
    tactic_ids=["TA0007"],
    mitre_url="https://attack.mitre.org/techniques/T1613/",
    threat_context=ThreatContext(
        description=(
            "Adversaries attempt to discover containers, images, deployments, pods, nodes, "
            "and cluster status information through Docker and Kubernetes APIs or web dashboards. "
            "This reconnaissance helps attackers understand the containerised environment to inform "
            "lateral movement and execution strategies."
        ),
        attacker_goal="Map container resources to identify targets and understand cluster topology",
        why_technique=[
            "Identifies running containers and workloads",
            "Reveals cluster architecture and nodes",
            "Discovers container images for exploitation",
            "Maps network topology between pods",
            "Finds exposed dashboards and APIs",
            "Required for targeted container attacks",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=6,
        severity_reasoning=(
            "Discovery activity with moderate-high impact. Indicates active reconnaissance "
            "of container infrastructure. Typically precedes container escape, lateral movement, "
            "or cryptomining deployment."
        ),
        business_impact=[
            "Reveals container architecture",
            "Identifies vulnerable workloads",
            "Enables targeted container attacks",
            "Early warning for container breaches",
            "May indicate cryptomining preparation",
        ],
        typical_attack_phase="discovery",
        often_precedes=["T1525", "T1496.001", "T1190", "T1610"],
        often_follows=["T1078.004", "T1190", "T1552.005"],
    ),
    detection_strategies=[
        # Strategy 1: AWS - ECS/EKS API Enumeration
        DetectionStrategy(
            strategy_id="t1613-aws-container",
            name="AWS ECS/EKS Container Discovery Detection",
            description="Detect container and cluster enumeration via AWS APIs.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, userIdentity.arn, requestParameters
| filter eventSource in ["ecs.amazonaws.com", "eks.amazonaws.com"]
| filter eventName in ["ListClusters", "DescribeClusters", "ListTasks", "DescribeTasks", "ListContainerInstances", "DescribeContainerInstances", "ListServices", "DescribeServices", "ListPods", "DescribeNodegroup"]
| stats count(*) as discovery_count by userIdentity.arn, bin(1h)
| filter discovery_count > 30
| sort discovery_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect container and resource discovery

Parameters:
  CloudTrailLogGroup:
    Type: String
  AlertEmail:
    Type: String

Resources:
  # Step 1: SNS topic
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter
  ContainerDiscoveryFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventSource = "ecs.amazonaws.com" || $.eventSource = "eks.amazonaws.com") && ($.eventName = "ListClusters" || $.eventName = "DescribeClusters" || $.eventName = "ListTasks" || $.eventName = "DescribeTasks" || $.eventName = "ListContainerInstances") }'
      MetricTransformations:
        - MetricName: ContainerDiscovery
          MetricNamespace: Security
          MetricValue: "1"

  # Step 3: Alarm
  ContainerDiscoveryAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: ContainerResourceDiscovery
      MetricName: ContainerDiscovery
      Namespace: Security
      Statistic: Sum
      Period: 300
      Threshold: 50
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
          - Sid: AllowCloudWatchAlarms
            Effect: Allow
            Principal:
              Service: cloudwatch.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId""",
                terraform_template="""# Detect container and resource discovery

variable "cloudtrail_log_group" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "container-discovery-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter
resource "aws_cloudwatch_log_metric_filter" "container_discovery" {
  name           = "container-discovery"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventSource = \"ecs.amazonaws.com\" || $.eventSource = \"eks.amazonaws.com\") && ($.eventName = \"ListClusters\" || $.eventName = \"DescribeClusters\" || $.eventName = \"ListTasks\" || $.eventName = \"DescribeTasks\" || $.eventName = \"ListContainerInstances\") }"

  metric_transformation {
    name      = "ContainerDiscovery"
    namespace = "Security"
    value     = "1"
  }
}

# Step 3: Alarm
resource "aws_cloudwatch_metric_alarm" "container_discovery" {
  alarm_name          = "ContainerResourceDiscovery"
  metric_name         = "ContainerDiscovery"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 50
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.alerts.arn]
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "alerts" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchAlarms"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
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
                alert_severity="medium",
                alert_title="Container Resource Discovery Detected",
                alert_description_template="High volume of container/cluster discovery calls from {userIdentity.arn}.",
                investigation_steps=[
                    "Identify who is enumerating containers",
                    "Check if this is authorised monitoring/scanning",
                    "Review what resources were discovered",
                    "Look for follow-on container access or deployment activity",
                    "Check for Docker/Kubernetes API access logs",
                    "Verify source IP addresses",
                ],
                containment_actions=[
                    "Review user's ECS/EKS permissions",
                    "Monitor for container deployments or exec commands",
                    "Consider restricting list/describe permissions",
                    "Enable EKS audit logging if not enabled",
                    "Review container security posture",
                    "Audit recent container activity",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Whitelist container monitoring tools, CSPM scanners, and orchestration platforms",
            detection_coverage="75% - volume-based, catches bulk enumeration",
            evasion_considerations="Slow, distributed enumeration evades volume thresholds",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail logging to CloudWatch", "ECS/EKS in use"],
        ),
        # Strategy 2: AWS - Kubernetes API Server Audit Logs
        DetectionStrategy(
            strategy_id="t1613-aws-k8s-audit",
            name="AWS EKS Kubernetes API Audit Detection",
            description="Detect kubectl commands via EKS audit logs.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, user.username, verb, objectRef.resource, objectRef.name, sourceIPs
| filter verb in ["list", "get"]
| filter objectRef.resource in ["pods", "nodes", "deployments", "services", "containers", "namespaces", "secrets"]
| stats count(*) as discovery_count by user.username, bin(30m)
| filter discovery_count > 50
| sort discovery_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect Kubernetes resource discovery

Parameters:
  EKSAuditLogGroup:
    Type: String
    Description: EKS cluster audit log group
  AlertEmail:
    Type: String

Resources:
  # Step 1: SNS topic
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter
  K8sDiscoveryFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref EKSAuditLogGroup
      FilterPattern: '{ ($.verb = "list" || $.verb = "get") && ($.objectRef.resource = "pods" || $.objectRef.resource = "nodes" || $.objectRef.resource = "deployments" || $.objectRef.resource = "services") }'
      MetricTransformations:
        - MetricName: K8sResourceDiscovery
          MetricNamespace: Security
          MetricValue: "1"

  # Step 3: Alarm
  K8sDiscoveryAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: K8sResourceDiscovery
      MetricName: K8sResourceDiscovery
      Namespace: Security
      Statistic: Sum
      Period: 1800
      Threshold: 100
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
          - Sid: AllowCloudWatchAlarms
            Effect: Allow
            Principal:
              Service: cloudwatch.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId""",
                terraform_template="""# Detect Kubernetes resource discovery

variable "eks_audit_log_group" {
  type        = string
  description = "EKS cluster audit log group"
}

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "k8s-discovery-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter
resource "aws_cloudwatch_log_metric_filter" "k8s_discovery" {
  name           = "k8s-resource-discovery"
  log_group_name = var.eks_audit_log_group
  pattern        = "{ ($.verb = \"list\" || $.verb = \"get\") && ($.objectRef.resource = \"pods\" || $.objectRef.resource = \"nodes\" || $.objectRef.resource = \"deployments\" || $.objectRef.resource = \"services\") }"

  metric_transformation {
    name      = "K8sResourceDiscovery"
    namespace = "Security"
    value     = "1"
  }
}

# Step 3: Alarm
resource "aws_cloudwatch_metric_alarm" "k8s_discovery" {
  alarm_name          = "K8sResourceDiscovery"
  metric_name         = "K8sResourceDiscovery"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 1800
  threshold           = 100
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.alerts.arn]
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "alerts" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchAlarms"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
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
                alert_severity="medium",
                alert_title="Kubernetes Resource Discovery Detected",
                alert_description_template="High volume of kubectl get/list commands from {user.username}.",
                investigation_steps=[
                    "Identify the Kubernetes user/service account",
                    "Check if this is authorised automation",
                    "Review what resources were queried",
                    "Check for subsequent exec or deployment commands",
                    "Verify source IP addresses",
                    "Review RBAC permissions",
                ],
                containment_actions=[
                    "Review service account permissions",
                    "Monitor for container exec or port-forward activity",
                    "Enable pod security policies",
                    "Restrict discovery permissions with RBAC",
                    "Review recent pod deployments",
                    "Check for suspicious containers",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Whitelist monitoring service accounts, operators, and controllers",
            detection_coverage="80% - captures kubectl activity",
            evasion_considerations="Direct API calls may bypass logging if audit policy not configured",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1.5 hours",
            estimated_monthly_cost="$10-15",
            prerequisites=["EKS cluster with audit logging enabled"],
        ),
        # Strategy 3: GCP - GKE Enumeration Detection
        DetectionStrategy(
            strategy_id="t1613-gcp-gke",
            name="GCP GKE Container Discovery Detection",
            description="Detect container and cluster enumeration via GCP APIs.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName=~"(container.clusters.list|container.clusters.get|io.k8s.core.v1.pods.list|io.k8s.core.v1.nodes.list|io.k8s.apps.v1.deployments.list|io.k8s.core.v1.services.list|io.k8s.core.v1.namespaces.list)"''',
                gcp_terraform_template="""# GCP: Detect container resource discovery

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric
resource "google_logging_metric" "container_discovery" {
  project = var.project_id
  name   = "container-resource-discovery"
  filter = <<-EOT
    protoPayload.methodName=~"(container.clusters.list|container.clusters.get|io.k8s.core.v1.pods.list|io.k8s.core.v1.nodes.list|io.k8s.apps.v1.deployments.list)"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "container_discovery" {
  project      = var.project_id
  display_name = "Container Resource Discovery"
  combiner     = "OR"

  conditions {
    display_name = "High volume container discovery"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.container_discovery.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 100
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }
}""",
                alert_severity="medium",
                alert_title="GCP: Container Resource Discovery",
                alert_description_template="High volume of container/cluster discovery calls detected.",
                investigation_steps=[
                    "Identify the enumerating principal/service account",
                    "Check if this is authorised monitoring",
                    "Review what resources were discovered",
                    "Look for follow-on container access",
                    "Check GKE audit logs for kubectl activity",
                    "Verify source IP addresses",
                ],
                containment_actions=[
                    "Review IAM and RBAC permissions",
                    "Monitor for container exec or deployment",
                    "Enable Binary Authorisation",
                    "Restrict discovery permissions",
                    "Review recent container activity",
                    "Audit service account usage",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Whitelist monitoring service accounts, GKE operators, and CSPM tools",
            detection_coverage="75% - volume-based detection",
            evasion_considerations="Slow enumeration evades volume thresholds",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-15",
            prerequisites=["Cloud Audit Logs enabled", "GKE in use"],
        ),
        # Strategy 4: GCP - Kubernetes Audit Logs
        DetectionStrategy(
            strategy_id="t1613-gcp-k8s-audit",
            name="GCP GKE Kubernetes API Audit Detection",
            description="Detect kubectl enumeration commands via GKE audit logs.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="k8s_cluster"
protoPayload.request.verb=~"(list|get)"
protoPayload.resourceName=~"(pods|nodes|deployments|services|namespaces|secrets|containers)"''',
                gcp_terraform_template="""# GCP: Detect Kubernetes resource discovery

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric
resource "google_logging_metric" "k8s_discovery" {
  project = var.project_id
  name   = "k8s-resource-discovery"
  filter = <<-EOT
    resource.type="k8s_cluster"
    protoPayload.request.verb=~"(list|get)"
    protoPayload.resourceName=~"(pods|nodes|deployments|services)"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "k8s_discovery" {
  project      = var.project_id
  display_name = "Kubernetes Resource Discovery"
  combiner     = "OR"

  conditions {
    display_name = "High volume kubectl discovery"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.k8s_discovery.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 150
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }
}""",
                alert_severity="medium",
                alert_title="GCP: Kubernetes Resource Discovery",
                alert_description_template="High volume kubectl get/list commands detected.",
                investigation_steps=[
                    "Identify the Kubernetes user/service account",
                    "Check if this is authorised automation",
                    "Review what resources were queried",
                    "Check for subsequent exec or deployment commands",
                    "Verify source IP and authentication method",
                    "Review RBAC bindings",
                ],
                containment_actions=[
                    "Review service account RBAC permissions",
                    "Monitor for exec or port-forward activity",
                    "Enable GKE security features",
                    "Restrict discovery with RBAC",
                    "Review recent pod deployments",
                    "Enable Binary Authorisation",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Whitelist monitoring service accounts and GKE controllers",
            detection_coverage="80% - captures kubectl activity",
            evasion_considerations="Direct API calls without proper audit logging configuration",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-15",
            prerequisites=["GKE cluster with audit logging enabled"],
        ),
    ],
    recommended_order=[
        "t1613-aws-container",
        "t1613-aws-k8s-audit",
        "t1613-gcp-gke",
        "t1613-gcp-k8s-audit",
    ],
    total_effort_hours=4.5,
    coverage_improvement="+12% improvement for Discovery tactic",
)
