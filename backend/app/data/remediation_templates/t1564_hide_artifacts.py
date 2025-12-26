"""
T1564 - Hide Artifacts

Adversaries attempt to hide artefacts tied to their activities to evade detection. This includes
exploiting OS features that hide system files, creating isolated computing environments like virtual
instances, and using cloud-native features to conceal malicious resources.
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
    technique_id="T1564",
    technique_name="Hide Artifacts",
    tactic_ids=["TA0005"],
    mitre_url="https://attack.mitre.org/techniques/T1564/",
    threat_context=ThreatContext(
        description=(
            "Adversaries attempt to hide artefacts tied to their activities to evade detection. "
            "In cloud environments, this includes creating hidden resources, using uncommon regions, "
            "manipulating resource tags to avoid monitoring, running virtual instances within compromised "
            "instances, and exploiting serverless environments to conceal malicious operations."
        ),
        attacker_goal="Conceal malicious resources and activities to avoid detection and maintain persistence",
        why_technique=[
            "Allows malicious infrastructure to operate undetected",
            "Bypasses standard security monitoring focused on common patterns",
            "Creates isolated environments for command and control",
            "Reduces likelihood of investigation during incident response",
            "Enables long-term persistence by avoiding cleanup efforts",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=7,
        severity_reasoning=(
            "Hiding artefacts indicates advanced adversary tradecraft and intent to maintain "
            "long-term access. While not immediately destructive, it enables persistent compromise "
            "and complicates incident response. The increasing use of cloud-native hiding techniques "
            "makes this a growing concern for cloud security teams."
        ),
        business_impact=[
            "Prolonged undetected compromise leading to data exfiltration",
            "Increased costs from hidden resource consumption (cryptomining, etc.)",
            "Difficulty in incident response and forensic investigation",
            "Compliance violations due to unmonitored resources",
            "Potential for hidden backdoors enabling future breaches",
        ],
        typical_attack_phase="defence_evasion",
        often_precedes=["T1496", "T1567", "T1537"],
        often_follows=["T1078.004", "T1098", "T1136.003"],
    ),
    detection_strategies=[
        # Strategy 1: AWS - Unusual Region Activity
        DetectionStrategy(
            strategy_id="t1564-aws-unusual-region",
            name="Unusual Region Activity Detection",
            description=(
                "Detect resource creation in regions that are not typically used by the organisation, "
                "which may indicate attempts to hide malicious infrastructure."
            ),
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
                    "Persistence:IAMUser/ResourceCreation.OutsideNormalRegions",
                ],
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect resource creation in unusual regions

Parameters:
  AlertEmail:
    Type: String
  CloudTrailLogGroup:
    Type: String

Resources:
  # Step 1: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter for unusual region activity
  UnusualRegionFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventName = "RunInstances" || $.eventName = "CreateFunction" || $.eventName = "CreateDBInstance") && ($.awsRegion = "af-south-1" || $.awsRegion = "ap-east-1" || $.awsRegion = "me-south-1") }'
      MetricTransformations:
        - MetricName: UnusualRegionActivity
          MetricNamespace: Security/T1564
          MetricValue: "1"

  # Step 3: Alarm on unusual region activity
  UnusualRegionAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1564-UnusualRegionActivity
      AlarmDescription: Resources created in unusual regions
      MetricName: UnusualRegionActivity
      Namespace: Security/T1564
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 1
      ComparisonOperator: GreaterThanOrEqualToThreshold
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref AlertTopic

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref AlertTopic]
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: cloudwatch.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic""",
                terraform_template="""# Detect resource creation in unusual regions

variable "alert_email" {
  type = string
}

variable "cloudtrail_log_group" {
  type = string
}

# List of unusual regions (modify based on your organisation's usage)
variable "unusual_regions" {
  type    = list(string)
  default = ["af-south-1", "ap-east-1", "me-south-1", "me-central-1"]
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "unusual-region-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for unusual region activity
resource "aws_cloudwatch_log_metric_filter" "unusual_region" {
  name           = "unusual-region-activity"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventName = \"RunInstances\" || $.eventName = \"CreateFunction\" || $.eventName = \"CreateDBInstance\") && ($.awsRegion = \"af-south-1\" || $.awsRegion = \"ap-east-1\" || $.awsRegion = \"me-south-1\") }"

  metric_transformation {
    name      = "UnusualRegionActivity"
    namespace = "Security/T1564"
    value     = "1"
  }
}

# Step 3: Alarm on unusual region activity
resource "aws_cloudwatch_metric_alarm" "unusual_region" {
  alarm_name          = "T1564-UnusualRegionActivity"
  alarm_description   = "Resources created in unusual regions"
  metric_name         = "UnusualRegionActivity"
  namespace           = "Security/T1564"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="high",
                alert_title="Resource Created in Unusual Region",
                alert_description_template=(
                    "Resource of type {eventName} was created in unusual region {awsRegion} by {userIdentity.arn}. "
                    "This may indicate an attempt to hide malicious infrastructure."
                ),
                investigation_steps=[
                    "Identify the IAM principal that created the resource",
                    "Verify if the region is legitimately used by your organisation",
                    "Review all resources created in the unusual region",
                    "Check for similar activity across other unusual regions",
                    "Examine the resource configuration for malicious indicators",
                ],
                containment_actions=[
                    "Terminate or delete resources in unusual regions if unauthorised",
                    "Disable or quarantine the IAM principal if compromised",
                    "Implement Service Control Policies to restrict region usage",
                    "Review and update IAM policies to enforce region restrictions",
                    "Enable GuardDuty in all regions for comprehensive monitoring",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Customise unusual region list based on organisation's legitimate multi-region usage",
            detection_coverage="70% - focuses on common resource types in unusual regions",
            evasion_considerations="Attackers may use allowed regions or serverless resources to avoid detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled", "CloudTrail logs in CloudWatch"],
        ),
        # Strategy 2: AWS - Hidden Lambda Functions
        DetectionStrategy(
            strategy_id="t1564-aws-hidden-lambda",
            name="Hidden Lambda Function Detection",
            description=(
                "Detect Lambda functions with minimal logging, unusual names, or configurations "
                "that suggest attempts to hide serverless backdoors."
            ),
            detection_type=DetectionType.CONFIG_RULE,
            aws_service="config",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, requestParameters.functionName, userIdentity.arn
| filter eventSource = "lambda.amazonaws.com"
| filter eventName = "CreateFunction20150331" or eventName = "UpdateFunctionConfiguration20150331v2"
| filter requestParameters.loggingConfig.logGroup = "" or ispresent(requestParameters.loggingConfig) = 0
| sort @timestamp desc
| limit 100""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect Lambda functions with minimal logging

Parameters:
  AlertEmail:
    Type: String

Resources:
  # Step 1: Config rule for Lambda logging
  LambdaLoggingRule:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: T1564-LambdaLoggingEnabled
      Description: Ensures Lambda functions have logging enabled
      Source:
        Owner: AWS
        SourceIdentifier: LAMBDA_CLOUDWATCH_LOGS_ENABLED
      Scope:
        ComplianceResourceTypes:
          - AWS::Lambda::Function

  # Step 2: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 3: EventBridge rule for non-compliant Lambda functions
  NonCompliantLambdaRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.config]
        detail-type: [Config Rules Compliance Change]
        detail:
          configRuleName: [T1564-LambdaLoggingEnabled]
          newEvaluationResult:
            complianceType: [NON_COMPLIANT]
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
            Resource: !Ref AlertTopic""",
                terraform_template="""# Detect Lambda functions with minimal logging

variable "alert_email" {
  type = string
}

# Step 1: Config rule for Lambda logging
resource "aws_config_config_rule" "lambda_logging" {
  name        = "T1564-LambdaLoggingEnabled"
  description = "Ensures Lambda functions have logging enabled"

  source {
    owner             = "AWS"
    source_identifier = "LAMBDA_CLOUDWATCH_LOGS_ENABLED"
  }

  scope {
    compliance_resource_types = ["AWS::Lambda::Function"]
  }

  depends_on = [aws_config_configuration_recorder.main]
}

# Step 2: SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "lambda-logging-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 3: EventBridge rule for non-compliant Lambda functions
resource "aws_cloudwatch_event_rule" "non_compliant_lambda" {
  name = "lambda-logging-violations"
  event_pattern = jsonencode({
    source      = ["aws.config"]
    detail-type = ["Config Rules Compliance Change"]
    detail = {
      configRuleName = ["T1564-LambdaLoggingEnabled"]
      newEvaluationResult = {
        complianceType = ["NON_COMPLIANT"]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.non_compliant_lambda.name
  arn  = aws_sns_topic.alerts.arn
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
}

# Note: Requires AWS Config to be enabled
resource "aws_config_configuration_recorder" "main" {
  name     = "config-recorder"
  role_arn = aws_iam_role.config.arn
}

resource "aws_iam_role" "config" {
  name = "config-recorder-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "config.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "config" {
  role       = aws_iam_role.config.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/ConfigRole"
}""",
                alert_severity="medium",
                alert_title="Lambda Function Without Proper Logging Detected",
                alert_description_template=(
                    "Lambda function {resourceId} does not have CloudWatch logging enabled. "
                    "This may indicate an attempt to hide serverless backdoor activity."
                ),
                investigation_steps=[
                    "Review the Lambda function code and configuration",
                    "Check when the function was created and by whom",
                    "Examine the function's execution history and triggers",
                    "Look for unusual environment variables or IAM roles",
                    "Search for similar functions with minimal logging",
                ],
                containment_actions=[
                    "Enable CloudWatch Logs for the function",
                    "Review and restrict the function's IAM permissions",
                    "Delete the function if unauthorised or malicious",
                    "Implement Lambda function naming standards",
                    "Use Lambda Insights for enhanced monitoring",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Create exceptions for test/development functions with documented purpose",
            detection_coverage="65% - covers Lambda functions but may miss other serverless services",
            evasion_considerations="Attackers may enable minimal logging or use alternative compute services",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$15-25",
            prerequisites=["AWS Config enabled", "Config recorder running"],
        ),
        # Strategy 3: GCP - Hidden Compute Instances
        DetectionStrategy(
            strategy_id="t1564-gcp-hidden-instances",
            name="GCP Hidden Compute Instance Detection",
            description=(
                "Detect Compute Engine instances with suspicious configurations such as "
                "disabled logging, unusual machine types, or misleading labels."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""protoPayload.methodName="v1.compute.instances.insert"
(protoPayload.request.metadata.items.key="enable-oslogin" AND protoPayload.request.metadata.items.value="false")
OR (protoPayload.request.disks.initializeParams.sourceImage=~".*minimal.*")""",
                gcp_terraform_template="""# GCP: Detect hidden compute instances

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

# Step 2: Log-based metric for suspicious instance creation
resource "google_logging_metric" "hidden_instances" {
  name   = "hidden-compute-instances"
  filter = <<-EOT
    protoPayload.methodName="v1.compute.instances.insert"
    (
      (protoPayload.request.metadata.items.key="enable-oslogin" AND protoPayload.request.metadata.items.value="false")
      OR protoPayload.request.disks.initializeParams.sourceImage=~".*minimal.*"
    )
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "hidden_instances" {
  display_name = "Hidden Compute Instance Detected"
  combiner     = "OR"

  conditions {
    display_name = "Suspicious instance created"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.hidden_instances.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "1800s"
  }

  documentation {
    content = "Compute instance created with suspicious configuration that may indicate hiding attempt. Review instance configuration and creator."
  }
}""",
                alert_severity="medium",
                alert_title="GCP: Hidden Compute Instance Detected",
                alert_description_template=(
                    "Compute instance created with suspicious configuration that may indicate hiding attempt. "
                    "Instance: {protoPayload.resourceName}, Creator: {protoPayload.authenticationInfo.principalEmail}"
                ),
                investigation_steps=[
                    "Review the instance configuration and labels",
                    "Check who created the instance and their recent activity",
                    "Examine the instance's network configuration and firewall rules",
                    "Look for unusual processes or software on the instance",
                    "Search for similar instances across projects",
                ],
                containment_actions=[
                    "Stop the instance if unauthorised",
                    "Enable OS Login and Cloud Logging on the instance",
                    "Review and restrict the creator's IAM permissions",
                    "Delete the instance if confirmed malicious",
                    "Implement organisation policies requiring logging",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline legitimate minimal image usage and OS Login disabled for specific workloads",
            detection_coverage="60% - focuses on common hiding patterns but may miss sophisticated techniques",
            evasion_considerations="Attackers may use legitimate configurations with subtle modifications",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
        # Strategy 4: GCP - Cloud Run Hidden Services
        DetectionStrategy(
            strategy_id="t1564-gcp-hidden-cloudrun",
            name="GCP Cloud Run Hidden Service Detection",
            description=(
                "Detect Cloud Run services deployed with minimal visibility, including "
                "services without proper logging or with restricted access patterns."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName=~"google.cloud.run.*.services.create"
protoPayload.serviceName="run.googleapis.com"''',
                gcp_terraform_template="""# GCP: Monitor Cloud Run service creation for hiding attempts

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

# Step 2: Log-based metric for Cloud Run service creation
resource "google_logging_metric" "cloudrun_creation" {
  name   = "cloudrun-service-creation"
  filter = <<-EOT
    protoPayload.methodName=~"google.cloud.run.*.services.create"
    protoPayload.serviceName="run.googleapis.com"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy for unusual Cloud Run deployments
resource "google_monitoring_alert_policy" "cloudrun_alert" {
  display_name = "Cloud Run Service Created"
  combiner     = "OR"

  conditions {
    display_name = "New Cloud Run service deployed"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.cloudrun_creation.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "1800s"
  }

  documentation {
    content = "Cloud Run service created. Review service configuration, logging settings, and access controls to ensure it's authorised and properly monitored."
  }
}""",
                alert_severity="medium",
                alert_title="GCP: Cloud Run Service Created",
                alert_description_template=(
                    "Cloud Run service {protoPayload.resourceName} was created by {protoPayload.authenticationInfo.principalEmail}. "
                    "Review for potential hiding attempt."
                ),
                investigation_steps=[
                    "Review the Cloud Run service configuration and code",
                    "Check if logging and monitoring are properly enabled",
                    "Examine the service's IAM bindings and access controls",
                    "Verify the container image source and registry",
                    "Look for unusual environment variables or secrets",
                ],
                containment_actions=[
                    "Delete the service if unauthorised",
                    "Enable Cloud Logging for the service",
                    "Restrict ingress to authorised sources only",
                    "Review and lock down the service account permissions",
                    "Implement Cloud Run deployment approval workflows",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Integrate with change management system; alert only on deployments outside approved windows",
            detection_coverage="50% - detects creation but requires manual review to identify hiding attempts",
            evasion_considerations="Attackers may use legitimate-looking service names and proper logging configuration",
            implementation_effort=EffortLevel.LOW,
            implementation_time="45 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
        # Strategy 5: AWS - Resource Tagging Anomalies
        DetectionStrategy(
            strategy_id="t1564-aws-tag-anomalies",
            name="Resource Tagging Anomaly Detection",
            description=(
                "Detect resources created without required tags or with misleading tags "
                "that may indicate attempts to hide from asset management and monitoring systems."
            ),
            detection_type=DetectionType.CONFIG_RULE,
            aws_service="config",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect resources with missing or suspicious tags

Parameters:
  AlertEmail:
    Type: String
  RequiredTagKeys:
    Type: CommaDelimitedList
    Default: "Environment,Owner,CostCentre"

Resources:
  # Step 1: Config rule for required tags
  RequiredTagsRule:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: T1564-RequiredTags
      Description: Ensures resources have required tags
      InputParameters:
        tag1Key: Environment
        tag2Key: Owner
        tag3Key: CostCentre
      Source:
        Owner: AWS
        SourceIdentifier: REQUIRED_TAGS

  # Step 2: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 3: EventBridge rule for non-compliant resources
  NonCompliantResourceRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.config]
        detail-type: [Config Rules Compliance Change]
        detail:
          configRuleName: [T1564-RequiredTags]
          newEvaluationResult:
            complianceType: [NON_COMPLIANT]
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
            Resource: !Ref AlertTopic""",
                terraform_template="""# Detect resources with missing or suspicious tags

variable "alert_email" {
  type = string
}

variable "required_tags" {
  type    = list(string)
  default = ["Environment", "Owner", "CostCentre"]
}

# Step 1: Config rule for required tags
resource "aws_config_config_rule" "required_tags" {
  name        = "T1564-RequiredTags"
  description = "Ensures resources have required tags"

  source {
    owner             = "AWS"
    source_identifier = "REQUIRED_TAGS"
  }

  input_parameters = jsonencode({
    tag1Key = var.required_tags[0]
    tag2Key = var.required_tags[1]
    tag3Key = var.required_tags[2]
  })

  depends_on = [aws_config_configuration_recorder.main]
}

# Step 2: SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "resource-tag-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 3: EventBridge rule for non-compliant resources
resource "aws_cloudwatch_event_rule" "non_compliant_tags" {
  name = "resource-tag-violations"
  event_pattern = jsonencode({
    source      = ["aws.config"]
    detail-type = ["Config Rules Compliance Change"]
    detail = {
      configRuleName = ["T1564-RequiredTags"]
      newEvaluationResult = {
        complianceType = ["NON_COMPLIANT"]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.non_compliant_tags.name
  arn  = aws_sns_topic.alerts.arn
}

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
}

# Note: Requires AWS Config to be enabled
resource "aws_config_configuration_recorder" "main" {
  name     = "config-recorder"
  role_arn = aws_iam_role.config.arn
}

resource "aws_iam_role" "config" {
  name = "config-recorder-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "config.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "config" {
  role       = aws_iam_role.config.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/ConfigRole"
}""",
                alert_severity="low",
                alert_title="Resource Created Without Required Tags",
                alert_description_template=(
                    "Resource {resourceType} {resourceId} does not have required tags. "
                    "Untagged resources may be attempts to hide infrastructure from monitoring."
                ),
                investigation_steps=[
                    "Identify which required tags are missing",
                    "Review who created the resource and when",
                    "Check if the resource creator has a pattern of skipping tags",
                    "Examine the resource type and configuration",
                    "Look for other untagged resources from the same creator",
                ],
                containment_actions=[
                    "Apply required tags to the resource or delete if unauthorised",
                    "Educate users on tagging requirements",
                    "Implement Service Control Policies to enforce tagging",
                    "Use Tag Policies for organisation-wide enforcement",
                    "Enable automated tagging for new resources",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Allow grace period for newly created resources; integrate with provisioning tools",
            detection_coverage="80% - excellent coverage for tag compliance across resource types",
            evasion_considerations="Attackers may apply fake tags that appear legitimate",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$15-25",
            prerequisites=["AWS Config enabled", "Tagging standards defined"],
        ),
    ],
    recommended_order=[
        "t1564-aws-unusual-region",
        "t1564-gcp-hidden-instances",
        "t1564-aws-hidden-lambda",
        "t1564-gcp-hidden-cloudrun",
        "t1564-aws-tag-anomalies",
    ],
    total_effort_hours=6.75,
    coverage_improvement="+30% improvement for Defence Evasion tactic",
)
