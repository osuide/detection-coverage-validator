"""
T1204.003 - User Execution: Malicious Image

Adversaries deploy backdoored container/VM images from public repositories.
Users unknowingly run malicious instances. Used by TeamTNT.
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
    technique_id="T1204.003",
    technique_name="User Execution: Malicious Image",
    tactic_ids=["TA0002"],
    mitre_url="https://attack.mitre.org/techniques/T1204/003/",
    threat_context=ThreatContext(
        description=(
            "Adversaries deploy backdoored container or VM images to public repositories. "
            "Users unknowingly download and deploy these images, bypassing initial access defenses."
        ),
        attacker_goal="Execute malicious code via trojanised container/VM images",
        why_technique=[
            "Users trust public repositories",
            "Images run with system privileges",
            "Hard to detect backdoors",
            "Deceptive naming tricks users",
            "Bypasses perimeter defenses",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="moderate",
        trend="increasing",
        severity_score=7,
        severity_reasoning=(
            "Execution via trusted-looking images. Hard to detect. "
            "Can lead to cryptomining or data theft."
        ),
        business_impact=[
            "Malware execution",
            "Cryptomining abuse",
            "Data exfiltration",
            "Credential theft",
        ],
        typical_attack_phase="execution",
        often_precedes=["T1496.001", "T1530"],
        often_follows=[],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1204003-aws-public",
            name="AWS Public Image Usage Detection",
            description="Detect EC2 instances launched from non-approved public AMIs.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, requestParameters.imageId, userIdentity.arn
| filter eventSource = "ec2.amazonaws.com"
| filter eventName = "RunInstances"
| filter requestParameters.imageId not like /^ami-[a-z0-9]+/ or requestParameters.imageId not like /approved/
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect usage of unapproved AMIs

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

  PublicAMIFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventName = "RunInstances" }'
      MetricTransformations:
        - MetricName: InstanceLaunches
          MetricNamespace: Security
          MetricValue: "1"

  AMIAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: InstanceLaunchAlert
      MetricName: InstanceLaunches
      Namespace: Security
      Statistic: Sum
      Period: 300
      Threshold: 0
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
                terraform_template="""# Detect usage of unapproved images

variable "cloudtrail_log_group" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "image-usage-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

data "aws_caller_identity" "current" {}

# Use Config rule to check approved AMIs
resource "aws_config_config_rule" "approved_amis" {
  name = "approved-amis-by-id"
  source {
    owner             = "AWS"
    source_identifier = "APPROVED_AMIS_BY_ID"
  }
  input_parameters = jsonencode({
    amiIds = "ami-xxxxxxxx,ami-yyyyyyyy"  # Your approved AMIs
  })
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
}""",
                alert_severity="high",
                alert_title="Unapproved Image Used",
                alert_description_template="Instance launched from potentially unapproved image {imageId}.",
                investigation_steps=[
                    "Verify image is from approved source",
                    "Check image for malware",
                    "Review who launched the instance",
                    "Check instance behaviour",
                ],
                containment_actions=[
                    "Terminate suspicious instances",
                    "Block unapproved AMIs via SCP",
                    "Require AMI approval process",
                    "Scan running containers",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Maintain approved image list",
            detection_coverage="70% - requires image whitelist",
            evasion_considerations="Attacker may use similar names",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$5-10",
            prerequisites=["Approved AMI list maintained"],
        ),
        DetectionStrategy(
            strategy_id="t1204003-gcp-public",
            name="GCP Public Image Usage Detection",
            description="Detect VMs launched from non-approved public images.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName="compute.instances.insert"
protoPayload.request.disks.initializeParams.sourceImage!~"projects/YOUR-PROJECT"''',
                gcp_terraform_template="""# GCP: Detect usage of unapproved images

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "external_image" {
  name   = "external-image-usage"
  filter = <<-EOT
    protoPayload.methodName="compute.instances.insert"
    NOT protoPayload.request.disks.initializeParams.sourceImage=~"projects/${var.project_id}"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "external_image" {
  project      = var.project_id
  display_name = "External Image Usage"
  combiner     = "OR"
  conditions {
    display_name = "Non-approved image used"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.external_image.name}\""
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
                alert_severity="high",
                alert_title="GCP: Unapproved Image Used",
                alert_description_template="VM launched from external image.",
                investigation_steps=[
                    "Verify image source",
                    "Check for malware",
                    "Review launcher",
                    "Check VM behaviour",
                ],
                containment_actions=[
                    "Delete suspicious VMs",
                    "Use org policies for images",
                    "Enable Binary Authorization",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Maintain approved image projects",
            detection_coverage="70% - requires image policy",
            evasion_considerations="Similar naming",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$10-15",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
        # Azure Strategy: User Execution: Malicious Image
        DetectionStrategy(
            strategy_id="t1204003-azure",
            name="Azure User Execution: Malicious Image Detection",
            description=(
                "Azure detection for User Execution: Malicious Image. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.SENTINEL_RULE,
            aws_service="n/a",
            azure_service="sentinel",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                azure_kql_query="""// Azure Container/VM Image Deployment Detection
// MITRE ATT&CK: T1204.003 - User Execution: Malicious Image
let lookback = 24h;
// Detect container deployments from external registries
AzureActivity
| where TimeGenerated > ago(lookback)
| where OperationNameValue has_any (
    "Microsoft.ContainerInstance/containerGroups/write",
    "Microsoft.ContainerService/managedClusters/agentPools/write",
    "Microsoft.Web/sites/write",
    "Microsoft.Compute/virtualMachines/write"
)
| where ActivityStatusValue == "Success"
| extend
    Properties = parse_json(Properties),
    ResourceDetails = parse_json(Properties).responseBody
| extend
    ContainerImage = tostring(ResourceDetails.properties.containers[0].properties.image),
    VMImageReference = tostring(ResourceDetails.properties.storageProfile.imageReference.id),
    ResourceName = tostring(split(Resource, "/")[-1])
| where isnotempty(ContainerImage) or isnotempty(VMImageReference)
// Flag external or untrusted sources
| extend
    IsExternalImage = ContainerImage !has ".azurecr.io" and isnotempty(ContainerImage),
    IsPublicImage = ContainerImage has_any ("docker.io", "gcr.io", "ghcr.io", "quay.io")
| project
    TimeGenerated,
    Caller,
    CallerIpAddress,
    OperationNameValue,
    ResourceName,
    ContainerImage,
    VMImageReference,
    IsExternalImage,
    IsPublicImage,
    SubscriptionId
| order by TimeGenerated desc""",
                sentinel_rule_query="""// Sentinel Analytics Rule: Malicious Container/VM Image Detection
// MITRE ATT&CK: T1204.003 - User Execution: Malicious Image
// Detects deployment of containers from untrusted registries
let lookback = 24h;
let trustedRegistries = dynamic([
    ".azurecr.io",
    "mcr.microsoft.com"
]);
// Container deployments
let ContainerDeployments = AzureActivity
| where TimeGenerated > ago(lookback)
| where OperationNameValue has_any (
    "Microsoft.ContainerInstance/containerGroups/write",
    "Microsoft.Web/sites/config/write"
)
| where ActivityStatusValue == "Success"
| extend
    Properties = parse_json(Properties),
    ResourceDetails = parse_json(Properties).responseBody
| extend
    ContainerImage = tostring(ResourceDetails.properties.containers[0].properties.image)
| where isnotempty(ContainerImage)
| extend
    IsTrusted = ContainerImage has_any (trustedRegistries),
    RegistryType = case(
        ContainerImage has "azurecr.io", "Azure Container Registry",
        ContainerImage has "mcr.microsoft.com", "Microsoft Container Registry",
        ContainerImage has "docker.io", "Docker Hub",
        ContainerImage has "gcr.io", "Google Container Registry",
        ContainerImage has "ghcr.io", "GitHub Container Registry",
        "Unknown/Custom"
    )
| where not(IsTrusted);
// VM deployments from marketplace or custom images
let VMDeployments = AzureActivity
| where TimeGenerated > ago(lookback)
| where OperationNameValue == "Microsoft.Compute/virtualMachines/write"
| where ActivityStatusValue == "Success"
| extend
    Properties = parse_json(Properties),
    ResourceDetails = parse_json(Properties).responseBody
| extend
    ImagePublisher = tostring(ResourceDetails.properties.storageProfile.imageReference.publisher),
    ImageOffer = tostring(ResourceDetails.properties.storageProfile.imageReference.offer),
    ImageSku = tostring(ResourceDetails.properties.storageProfile.imageReference.sku),
    CustomImageId = tostring(ResourceDetails.properties.storageProfile.imageReference.id)
| extend
    IsCustomImage = isnotempty(CustomImageId),
    ImageSource = iff(isnotempty(ImagePublisher), strcat(ImagePublisher, "/", ImageOffer), "Custom Image")
| where IsCustomImage or ImagePublisher !in ("MicrosoftWindowsServer", "Canonical", "RedHat");
// Combine and score
ContainerDeployments
| extend ResourceType = "Container", ImageInfo = ContainerImage
| union (
    VMDeployments
    | extend ResourceType = "VM", ImageInfo = ImageSource
)
| project
    TimeGenerated,
    Caller,
    CallerIpAddress,
    ResourceType,
    ImageInfo,
    RegistryType,
    SubscriptionId
| summarize
    DeploymentCount = count(),
    ImageSources = make_set(ImageInfo, 10),
    RegistryTypes = make_set(RegistryType, 5)
    by Caller, CallerIpAddress
| where DeploymentCount > 1 or RegistryTypes has "Unknown"
| extend RiskScore = DeploymentCount * 10
| order by RiskScore desc""",
                azure_terraform_template="""# Azure Detection for User Execution: Malicious Image
# MITRE ATT&CK: T1204.003

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
  description = "Resource group for Log Analytics workspace"
}

variable "log_analytics_workspace_id" {
  type        = string
  description = "Log Analytics workspace resource ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Action Group for alerts
resource "azurerm_monitor_action_group" "security_alerts" {
  name                = "user-execution--malicious-image-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "SecAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Scheduled Query Rule for detection
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "detection" {
  name                = "user-execution--malicious-image-detection"
  resource_group_name = var.resource_group_name
  location            = "uksouth"

  evaluation_frequency = "PT5M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 2

  criteria {
    query = <<-QUERY
// Sentinel Analytics Rule: User Execution: Malicious Image
// MITRE ATT&CK: T1204.003
let lookback = 24h;
let threshold = 5;
AzureActivity
| where TimeGenerated > ago(lookback)
| where CategoryValue == "Administrative"
| where ActivityStatusValue in ("Success", "Succeeded")
| summarize
    EventCount = count(),
    DistinctOperations = dcount(OperationNameValue),
    Operations = make_set(OperationNameValue, 20),
    Resources = make_set(Resource, 10),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by Caller, CallerIpAddress, SubscriptionId
| where EventCount > threshold
| extend
    AccountName = tostring(split(Caller, "@")[0]),
    AccountDomain = tostring(split(Caller, "@")[1])
| project
    TimeGenerated = LastSeen,
    AccountName,
    AccountDomain,
    Caller,
    CallerIpAddress,
    SubscriptionId,
    EventCount,
    DistinctOperations,
    Operations,
    Resources
    QUERY

    time_aggregation_method = "Count"
    threshold               = 1
    operator                = "GreaterThanOrEqual"

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  auto_mitigation_enabled = false

  action {
    action_groups = [azurerm_monitor_action_group.security_alerts.id]
  }

  description = "Detects User Execution: Malicious Image (T1204.003) activity in Azure environment"
  display_name = "User Execution: Malicious Image Detection"
  enabled      = true

  tags = {
    "mitre-technique" = "T1204.003"
    "detection-type"  = "security"
  }
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.detection.id
}""",
                alert_severity="high",
                alert_title="Azure: User Execution: Malicious Image Detected",
                alert_description_template=(
                    "User Execution: Malicious Image activity detected. "
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
    recommended_order=["t1204003-aws-public", "t1204003-gcp-public"],
    total_effort_hours=4.0,
    coverage_improvement="+12% improvement for Execution tactic",
)
