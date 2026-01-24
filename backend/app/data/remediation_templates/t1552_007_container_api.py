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
        # Azure Strategy: Unsecured Credentials: Container API
        DetectionStrategy(
            strategy_id="t1552007-azure",
            name="Azure Unsecured Credentials: Container API Detection",
            description=(
                "Azure detection for Unsecured Credentials: Container API. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.DEFENDER_ALERT,
            aws_service="n/a",
            azure_service="defender",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                azure_kql_query="""// Direct KQL Query: Detect Container API Credential Access
// MITRE ATT&CK: T1552.007 - Unsecured Credentials: Container API
// Data Sources: AKSAuditLogs, AzureActivity, ContainerRegistryLoginEvents

// Part 1: Detect AKS secrets access
let AKSSecretAccess = AKSAuditLogs
| where TimeGenerated > ago(24h)
| where log_s has "secrets"
| extend LogData = parse_json(log_s)
| where LogData.verb in ("get", "list", "watch")
| where LogData.objectRef.resource == "secrets"
| extend
    Namespace = tostring(LogData.objectRef.namespace),
    SecretName = tostring(LogData.objectRef.name),
    Username = tostring(LogData.user.username),
    SourceIP = tostring(LogData.sourceIPs[0])
| summarize
    SecretAccessCount = count(),
    Secrets = make_set(SecretName, 20),
    Namespaces = make_set(Namespace, 10),
    FirstAccess = min(TimeGenerated),
    LastAccess = max(TimeGenerated)
    by Username, SourceIP, _ResourceId
| extend AccessType = "AKS Secrets";
// Part 2: Detect Container Registry access
let ACRAccess = ContainerRegistryLoginEvents
| where TimeGenerated > ago(24h)
| summarize
    LoginCount = count(),
    Registries = make_set(Registry, 10),
    FirstLogin = min(TimeGenerated),
    LastLogin = max(TimeGenerated)
    by Identity, ClientIP, LoginResult
| extend AccessType = "Container Registry";
// Part 3: Detect AKS cluster operations that could expose secrets
let AKSConfigAccess = AzureActivity
| where TimeGenerated > ago(24h)
| where OperationNameValue has "Microsoft.ContainerService/managedClusters"
| where OperationNameValue has_any ("listClusterAdminCredential", "listClusterUserCredential", "accessProfiles/read")
| summarize
    CredentialAccessCount = count(),
    Operations = make_set(OperationNameValue, 10),
    Clusters = make_set(Resource, 10),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by Caller, CallerIpAddress, SubscriptionId
| extend AccessType = "AKS Credentials";
// Combine results
AKSSecretAccess
| project
    TimeGenerated = LastAccess,
    AccessType,
    Caller = Username,
    CallerIpAddress = SourceIP,
    Resource = _ResourceId,
    AccessCount = SecretAccessCount,
    ItemsAccessed = Secrets,
    TechniqueId = "T1552.007",
    TechniqueName = "Container API Credentials",
    Severity = "High" """,
                sentinel_rule_query="""// Sentinel Analytics Rule: Container API Credential Access
// MITRE ATT&CK: T1552.007
// Detects AKS secrets access and Container Registry operations

// AKS secrets access
let AKSSecrets = AKSAuditLogs
| where TimeGenerated > ago(24h)
| where log_s has "secrets"
| extend LogData = parse_json(log_s)
| where LogData.verb in ("get", "list", "watch")
| where LogData.objectRef.resource == "secrets"
| extend
    Namespace = tostring(LogData.objectRef.namespace),
    SecretName = tostring(LogData.objectRef.name),
    Username = tostring(LogData.user.username),
    SourceIP = tostring(LogData.sourceIPs[0])
| summarize
    SecretCount = count(),
    Secrets = make_set(SecretName, 10),
    Namespaces = make_set(Namespace, 5),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by Username, SourceIP, _ResourceId
| where SecretCount > 5;  // Alert on bulk access
// AKS credential listing
let AKSCreds = AzureActivity
| where TimeGenerated > ago(24h)
| where OperationNameValue has "Microsoft.ContainerService/managedClusters"
| where OperationNameValue has_any ("listClusterAdminCredential", "listClusterUserCredential")
| summarize
    CredCount = count(),
    Clusters = make_set(Resource, 5),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by Caller, CallerIpAddress;
AKSSecrets
| project
    TimeGenerated = LastSeen,
    AccessType = "AKS Secrets",
    Caller = Username,
    CallerIpAddress = SourceIP,
    Cluster = _ResourceId,
    SecretCount,
    Secrets,
    Namespaces,
    FirstSeen""",
                defender_alert_types=["Suspicious activity detected"],
                azure_terraform_template="""# Microsoft Defender for Cloud Detection
# Unsecured Credentials: Container API (T1552.007)
# Microsoft Defender detects Unsecured Credentials: Container API activity

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
  name                = "defender-t1552-007-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "DefAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Log Analytics query for Defender alerts
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "defender_detection" {
  name                = "defender-t1552-007"
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

  description = "Microsoft Defender detects Unsecured Credentials: Container API activity"
  display_name = "Defender: Unsecured Credentials: Container API"
  enabled      = true

  tags = {
    "mitre-technique" = "T1552.007"
    "detection-type"  = "security"
  }
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.defender_detection.id
}""",
                alert_severity="high",
                alert_title="Azure: Unsecured Credentials: Container API Detected",
                alert_description_template=(
                    "Unsecured Credentials: Container API activity detected. "
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
        "t1552-007-aws-eks-secrets",
        "t1552-007-gcp-gke-secrets",
        "t1552-007-aws-docker-api",
        "t1552-007-gcp-docker-registry",
    ],
    total_effort_hours=5.5,
    coverage_improvement="+25% improvement for Credential Access tactic",
)
