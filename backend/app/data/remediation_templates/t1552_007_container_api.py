"""
T1552.007 - Unsecured Credentials: Container API

Adversaries exploit container environment APIs to obtain credentials from Docker,
Kubernetes, and cloud container services. Used by Peirates.
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
    technique_id="T1552.007",
    technique_name="Unsecured Credentials: Container API",
    tactic_ids=["TA0006"],
    mitre_url="https://attack.mitre.org/techniques/T1552/007/",
    threat_context=ThreatContext(
        description=(
            "Adversaries exploit container environment APIs to obtain credentials. "
            "Attackers may access the Docker API to harvest logs containing credentials "
            "for cloud services, containers, and other resources. With sufficient "
            "permissions, adversaries can query the Kubernetes API server to retrieve "
            "credentials needed for Docker authentication or extract secrets from cluster components."
        ),
        attacker_goal="Harvest credentials from container APIs including Docker and Kubernetes",
        why_technique=[
            "Docker API logs often contain credentials",
            "Kubernetes API exposes cluster secrets",
            "Service account tokens enable privilege escalation",
            "Unsecured APIs accessible without authentication",
            "Cloud container services expose native APIs",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="uncommon",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "Direct credential access technique targeting container environments. "
            "Successful exploitation provides access to cloud credentials, container "
            "secrets, and enables lateral movement across containerised infrastructure."
        ),
        business_impact=[
            "Cloud credential theft",
            "Container secret exposure",
            "Privilege escalation risk",
            "Lateral movement enabler",
        ],
        typical_attack_phase="credential_access",
        often_precedes=["T1078.004", "T1068", "T1610"],
        often_follows=["T1133", "T1190"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1552-007-aws-eks-secrets",
            name="AWS EKS Kubernetes API Secret Access Detection",
            description="Detect unauthorised access to Kubernetes secrets via API server.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, user.username, objectRef.namespace, objectRef.name, responseStatus.code
| filter objectRef.resource = "secrets"
| filter verb = "get" or verb = "list"
| filter userAgent not like /kube-controller|kube-scheduler|kubelet/
| stats count(*) as secret_access by user.username, bin(1h)
| filter secret_access > 10
| sort secret_access desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect unauthorised Kubernetes secret access

Parameters:
  EKSClusterName:
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
                AWS:SourceAccount: !Ref AWS::AccountId

  SecretAccessFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Sub '/aws/eks/${EKSClusterName}/cluster'
      FilterPattern: '{ $.objectRef.resource = "secrets" && ($.verb = "get" || $.verb = "list") }'
      MetricTransformations:
        - MetricName: KubernetesSecretAccess
          MetricNamespace: Security/EKS
          MetricValue: "1"

  SecretAccessAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: HighKubernetesSecretAccess
      MetricName: KubernetesSecretAccess
      Namespace: Security/EKS
      Statistic: Sum
      Period: 300
      Threshold: 20
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect unauthorised Kubernetes secret access

variable "eks_cluster_name" { type = string }
variable "alert_email" { type = string }

data "aws_caller_identity" "current" {}

resource "aws_sns_topic" "alerts" {
  name = "eks-secret-access-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchPublish"
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
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "secret_access" {
  name           = "kubernetes-secret-access"
  log_group_name = "/aws/eks/${var.eks_cluster_name}/cluster"
  pattern        = "{ $.objectRef.resource = \"secrets\" && ($.verb = \"get\" || $.verb = \"list\") }"

  metric_transformation {
    name      = "KubernetesSecretAccess"
    namespace = "Security/EKS"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "secret_access" {
  alarm_name          = "HighKubernetesSecretAccess"
  metric_name         = "KubernetesSecretAccess"
  namespace           = "Security/EKS"
  statistic           = "Sum"
  period              = 300
  threshold           = 20
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="high",
                alert_title="Kubernetes Secret Access Detected",
                alert_description_template="Unusual Kubernetes secret access from {username}.",
                investigation_steps=[
                    "Review user identity and permissions",
                    "Check which secrets were accessed",
                    "Review pod service account permissions",
                    "Check for unauthorised API access patterns",
                ],
                containment_actions=[
                    "Revoke compromised service account tokens",
                    "Review and restrict RBAC permissions",
                    "Enable Kubernetes audit logging",
                    "Rotate exposed secrets",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude legitimate system components via userAgent filtering",
            detection_coverage="70% - catches API-based secret access",
            evasion_considerations="Attackers may use legitimate service accounts",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-25",
            prerequisites=["EKS cluster with audit logging enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1552-007-aws-docker-api",
            name="AWS Docker API Unauthorised Access Detection",
            description="Detect unauthorised access to Docker API endpoints.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, sourceIPAddress, requestParameters, responseElements
| filter eventName like /Container|Task/
| filter eventName = "DescribeTaskDefinition" or eventName = "ListTasks" or eventName = "DescribeContainerInstances"
| filter errorCode not like /.*/
| stats count(*) as api_calls by sourceIPAddress, userIdentity.principalId, bin(1h)
| filter api_calls > 50
| sort api_calls desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect unauthorised Docker/ECS API access

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
                AWS:SourceAccount: !Ref AWS::AccountId

  DockerAPIAccessFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventName = "DescribeTaskDefinition" || $.eventName = "ListTasks") && $.errorCode NOT EXISTS }'
      MetricTransformations:
        - MetricName: DockerAPIAccess
          MetricNamespace: Security/ECS
          MetricValue: "1"

  DockerAPIAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: HighDockerAPIAccess
      MetricName: DockerAPIAccess
      Namespace: Security/ECS
      Statistic: Sum
      Period: 300
      Threshold: 100
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect unauthorised Docker/ECS API access

variable "cloudtrail_log_group" { type = string }
variable "alert_email" { type = string }

data "aws_caller_identity" "current" {}

resource "aws_sns_topic" "alerts" {
  name = "docker-api-access-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchPublish"
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
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "docker_api" {
  name           = "docker-api-access"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventName = \"DescribeTaskDefinition\" || $.eventName = \"ListTasks\") && $.errorCode NOT EXISTS }"

  metric_transformation {
    name      = "DockerAPIAccess"
    namespace = "Security/ECS"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "docker_api" {
  alarm_name          = "HighDockerAPIAccess"
  metric_name         = "DockerAPIAccess"
  namespace           = "Security/ECS"
  statistic           = "Sum"
  period              = 300
  threshold           = 100
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="medium",
                alert_title="Docker API Access Detected",
                alert_description_template="High volume of Docker/ECS API calls from {sourceIPAddress}.",
                investigation_steps=[
                    "Review API caller identity",
                    "Check accessed task definitions",
                    "Review container logs accessed",
                    "Check for credential exposure in logs",
                ],
                containment_actions=[
                    "Restrict API access permissions",
                    "Review IAM policies for over-permissive access",
                    "Enable VPC endpoint policies",
                    "Rotate exposed credentials",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Adjust threshold for CI/CD and monitoring tools",
            detection_coverage="60% - catches ECS API access patterns",
            evasion_considerations="Low-volume access may evade detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled with ECS data events"],
        ),
        DetectionStrategy(
            strategy_id="t1552-007-gcp-gke-secrets",
            name="GCP GKE Kubernetes Secret Access Detection",
            description="Detect unauthorised access to Kubernetes secrets in GKE.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="k8s_cluster"
protoPayload.methodName=~"io.k8s.core.v1.secrets.(get|list)"
protoPayload.authenticationInfo.principalEmail!~"system:serviceaccount:kube-system:"''',
                gcp_terraform_template="""# GCP: Detect Kubernetes secret access in GKE

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "secret_access" {
  project = var.project_id
  name   = "gke-secret-access"
  filter = <<-EOT
    resource.type="k8s_cluster"
    protoPayload.methodName=~"io.k8s.core.v1.secrets.(get|list)"
    protoPayload.authenticationInfo.principalEmail!~"system:serviceaccount:kube-system:"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "principal"
      value_type  = "STRING"
      description = "Principal accessing secrets"
    }
  }
  label_extractors = {
    "principal" = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
  }
}

resource "google_monitoring_alert_policy" "secret_access" {
  project      = var.project_id
  display_name = "GKE Secret Access Detected"
  combiner     = "OR"
  conditions {
    display_name = "High secret access rate"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.secret_access.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 20
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }
  notification_channels = [google_monitoring_notification_channel.email_s1.id]
  alert_strategy {
    auto_close = "86400s"
    notification_rate_limit {
      period = "300s"
    }
  }
}""",
                alert_severity="high",
                alert_title="GCP: Kubernetes Secret Access",
                alert_description_template="Unauthorised Kubernetes secret access detected.",
                investigation_steps=[
                    "Review principal identity",
                    "Check accessed secrets",
                    "Review RBAC permissions",
                    "Check for compromised service accounts",
                ],
                containment_actions=[
                    "Revoke service account tokens",
                    "Restrict RBAC permissions",
                    "Rotate exposed secrets",
                    "Enable Binary Authorisation",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude kube-system service accounts from alerts",
            detection_coverage="70% - catches API-based access",
            evasion_considerations="Legitimate service accounts may be compromised",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["GKE cluster with audit logging enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1552-007-gcp-docker-registry",
            name="GCP Container Registry Unauthorised Access",
            description="Detect unauthorised access to GCP Container Registry.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gcs_bucket"
protoPayload.resourceName=~".*gcr.io.*"
protoPayload.methodName="storage.objects.get"
protoPayload.authenticationInfo.principalEmail!~".*gserviceaccount.com"''',
                gcp_terraform_template="""# GCP: Detect Container Registry unauthorised access

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email_s2" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "registry_access" {
  project = var.project_id
  name   = "gcr-unauthorised-access"
  filter = <<-EOT
    resource.type="gcs_bucket"
    protoPayload.resourceName=~".*gcr.io.*"
    protoPayload.methodName="storage.objects.get"
    protoPayload.authenticationInfo.principalEmail!~".*gserviceaccount.com"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "principal"
      value_type  = "STRING"
      description = "Principal accessing registry"
    }
  }
  label_extractors = {
    "principal" = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
  }
}

resource "google_monitoring_alert_policy" "registry_access" {
  project      = var.project_id
  display_name = "Container Registry Unauthorised Access"
  combiner     = "OR"
  conditions {
    display_name = "Unusual registry access"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.registry_access.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 10
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
                alert_title="GCP: Container Registry Access",
                alert_description_template="Unauthorised Container Registry access detected.",
                investigation_steps=[
                    "Review accessing principal",
                    "Check accessed container images",
                    "Review IAM permissions",
                    "Check for credential exposure",
                ],
                containment_actions=[
                    "Restrict registry IAM permissions",
                    "Enable Binary Authorisation",
                    "Review service account keys",
                    "Rotate exposed credentials",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Exclude service account access patterns",
            detection_coverage="60% - catches direct access",
            evasion_considerations="Service account compromise may appear legitimate",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-15",
            prerequisites=["GCS audit logging enabled"],
        ),
    ],
    recommended_order=[
        "t1552-007-aws-eks-secrets",
        "t1552-007-gcp-gke-secrets",
        "t1552-007-aws-docker-api",
        "t1552-007-gcp-docker-registry",
    ],
    total_effort_hours=5.5,
    coverage_improvement="+25% improvement for Credential Access tactic",
)
