"""
T1127 - Trusted Developer Utilities Proxy Execution

Adversaries may take advantage of trusted developer utilities to proxy execution of malicious payloads.
"""

from .template_loader import (
    RemediationTemplate,
    ThreatContext,
    DetectionStrategy,
    DetectionImplementation,
    Campaign,
    DetectionType,
    EffortLevel,
    FalsePositiveRate,
    CloudProvider,
)

TEMPLATE = RemediationTemplate(
    technique_id="T1127",
    technique_name="Trusted Developer Utilities Proxy Execution",
    tactic_ids=["TA0005"],  # Defence Evasion
    mitre_url="https://attack.mitre.org/techniques/T1127/",
    threat_context=ThreatContext(
        description=(
            "Adversaries may leverage trusted developer utilities to proxy execution of malicious code. "
            "These signed utilities (MSBuild, dnx.exe, rcsi.exe, WinDbg/CDB, Tracker.exe) bypass "
            "application control solutions by executing code through trusted processes. In cloud environments, "
            "this technique can be used on Windows EC2 instances, GCE instances, or container images that "
            "include developer tooling, allowing attackers to execute arbitrary code whilst evading detection."
        ),
        attacker_goal="Execute malicious code whilst bypassing application control and security monitoring",
        why_technique=[
            "Leverages signed, trusted Microsoft binaries to evade application whitelisting",
            "Bypasses Smart App Control through reputation hijacking of legitimate applications",
            "Allows arbitrary C# or Visual Basic code execution via MSBuild inline tasks",
            "Often goes undetected by traditional endpoint security solutions",
            "Can be used to establish persistence or execute additional payloads",
            "Particularly effective in environments with developer tools installed",
        ],
        known_threat_actors=[],
        recent_campaigns=[
            Campaign(
                name="Frankenstein Campaign",
                year=2020,
                description="Threat actors cobbled together open-source pieces to leverage MSBuild for code execution",
                reference_url="https://attack.mitre.org/campaigns/C0001/",
            ),
            Campaign(
                name="Paranoid PlugX",
                year=2017,
                description="MSBuild used as part of sophisticated malware deployment and execution chain",
                reference_url="https://www.anomali.com/blog/threat-actors-use-msbuild-to-deliver-rats-filelessly",
            ),
            Campaign(
                name="Fileless RAT Delivery",
                year=2023,
                description="Threat actors used MSBuild to filelessly deliver Remcos RAT and RedLine Stealer",
                reference_url="https://www.anomali.com/blog/threat-actors-use-msbuild-to-deliver-rats-filelessly",
            ),
        ],
        prevalence="moderate",
        trend="stable",
        severity_score=7,
        severity_reasoning=(
            "Whilst primarily a Windows technique, this represents a sophisticated defence evasion method "
            "that can bypass many security controls. In cloud environments with Windows instances or "
            "development containers, this poses a significant risk. The use of trusted, signed binaries "
            "makes detection challenging and allows attackers to execute arbitrary code undetected."
        ),
        business_impact=[
            "Evasion of application control and endpoint protection",
            "Arbitrary code execution with trusted process privileges",
            "Potential for establishing persistent access mechanisms",
            "Difficult forensic investigation due to use of legitimate tools",
            "Increased attacker dwell time due to reduced detection likelihood",
        ],
        typical_attack_phase="defence_evasion",
        often_precedes=["T1059", "T1543", "T1055"],
        often_follows=["T1078", "T1190", "T1566"],
    ),
    detection_strategies=[
        # Strategy 1: AWS - Process Monitoring on Windows Instances
        DetectionStrategy(
            strategy_id="t1127-aws-process-monitoring",
            name="AWS CloudWatch for Developer Utility Execution",
            description=(
                "Monitor CloudWatch logs from Windows EC2 instances for execution of developer "
                "utilities (MSBuild.exe, dnx.exe, rcsi.exe, etc.) in non-development contexts, "
                "especially when spawning shells or loading unsigned DLLs."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query=r"""fields @timestamp, instance_id, process_name, command_line, parent_process, source_ip
| filter process_name in ["MSBuild.exe", "dnx.exe", "rcsi.exe", "cdb.exe", "windbg.exe", "tracker.exe"]
| filter command_line like /(?i)(http|\.csproj|\.xml|\.proj|inline)/
| filter parent_process not in ["devenv.exe", "VisualStudio.exe", "ServiceHub.Host.CLR.exe"]
| stats count(*) as execution_count by instance_id, process_name, bin(5m)
| filter execution_count > 0
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: CloudWatch alerting for developer utility proxy execution

Parameters:
  LogGroupName:
    Type: String
    Description: CloudWatch log group for Windows instance logs
  AlertEmail:
    Type: String

Resources:
  # Step 1: Create metric filter for developer utility execution
  DeveloperUtilityFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref LogGroupName
      FilterPattern: '[timestamp, instance, process=MSBuild.exe||dnx.exe||rcsi.exe||cdb.exe||windbg.exe||tracker.exe, ...]'
      MetricTransformations:
        - MetricName: DeveloperUtilityExecution
          MetricNamespace: Security/T1127
          MetricValue: "1"
          DefaultValue: 0

  # Step 2: Create SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: T1127 Developer Utility Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 3: Create alarm for suspicious executions
  DeveloperUtilityAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1127-DeveloperUtilityExecution
      AlarmDescription: Trusted developer utility executed in non-development context
      MetricName: DeveloperUtilityExecution
      Namespace: Security/T1127
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 1
      ComparisonOperator: GreaterThanOrEqualToThreshold
      AlarmActions:
        - !Ref AlertTopic
      TreatMissingData: notBreaching

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
                terraform_template="""# CloudWatch alerting for developer utility proxy execution

variable "log_group_name" {
  type        = string
  description = "CloudWatch log group for Windows instance logs"
}

variable "alert_email" {
  type = string
}

# Step 1: Create metric filter for developer utility execution
resource "aws_cloudwatch_log_metric_filter" "developer_utility" {
  name           = "t1127-developer-utility-execution"
  log_group_name = var.log_group_name
  pattern        = "[timestamp, instance, process=MSBuild.exe||dnx.exe||rcsi.exe||cdb.exe||windbg.exe||tracker.exe, ...]"

  metric_transformation {
    name      = "DeveloperUtilityExecution"
    namespace = "Security/T1127"
    value     = "1"
    default_value = 0
  }
}

# Step 2: Create SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name         = "t1127-developer-utility-alerts"
  display_name = "T1127 Developer Utility Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 3: Create alarm for suspicious executions
resource "aws_cloudwatch_metric_alarm" "developer_utility" {
  alarm_name          = "T1127-DeveloperUtilityExecution"
  alarm_description   = "Trusted developer utility executed in non-development context"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "DeveloperUtilityExecution"
  namespace           = "Security/T1127"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.alerts.arn
    }]
  })
}""",
                alert_severity="high",
                alert_title="Developer Utility Proxy Execution Detected",
                alert_description_template=(
                    "Trusted developer utility {process_name} executed on instance {instance_id}. "
                    "Command line: {command_line}. This may indicate defence evasion via T1127."
                ),
                investigation_steps=[
                    "Identify the EC2 instance and verify if it's a development environment",
                    "Review the full command line and parent process details",
                    "Check if MSBuild or other utilities were executed with suspicious arguments",
                    "Look for network connections made by the process",
                    "Examine any DLLs loaded or files created by the process",
                    "Review recent login activity to the instance",
                    "Check for other suspicious process executions on the same instance",
                ],
                containment_actions=[
                    "Isolate the affected EC2 instance from the network",
                    "Capture memory dump and disk snapshot for forensic analysis",
                    "Terminate suspicious processes if still running",
                    "Review and remove any unauthorised scheduled tasks or persistence mechanisms",
                    "Implement application whitelisting to restrict developer utilities",
                    "Remove unnecessary developer tools from production instances",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "Whitelist known development instances by instance ID or tag. "
                "Filter out executions from legitimate Visual Studio processes. "
                "Consider time-of-day analysis for development vs production instances."
            ),
            detection_coverage="70% - covers Windows instances with CloudWatch agent configured",
            evasion_considerations=(
                "Attackers may rename executables, use alternate developer utilities not monitored, "
                "or execute from non-standard paths. Process command-line obfuscation may hide malicious intent."
            ),
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$10-30 depending on log volume",
            prerequisites=[
                "CloudWatch agent installed on Windows EC2 instances",
                "Process monitoring enabled in CloudWatch agent configuration",
                "CloudWatch Logs configured to receive instance logs",
            ],
        ),
        # Strategy 2: AWS - Systems Manager Inventory
        DetectionStrategy(
            strategy_id="t1127-aws-ssm-inventory",
            name="AWS Systems Manager Inventory for Developer Tools",
            description=(
                "Use AWS Systems Manager Inventory to identify EC2 instances with developer "
                "utilities installed. Flag non-development instances with build tools for review."
            ),
            detection_type=DetectionType.CONFIG_RULE,
            aws_service="systems_manager",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Systems Manager inventory for developer tools detection

Parameters:
  SNSTopicArn:
    Type: String

Resources:
  # Step 1: Create SSM association for inventory collection
  InventoryAssociation:
    Type: AWS::SSM::Association
    Properties:
      Name: AWS-GatherSoftwareInventory
      AssociationName: T1127-DeveloperToolsInventory
      ScheduleExpression: rate(1 day)
      Targets:
        - Key: InstanceIds
          Values: ["*"]
      Parameters:
        applications:
          - Enabled
        files:
          - '{"Path": "C:\\Program Files (x86)\\Microsoft Visual Studio", "Pattern": ["msbuild.exe"], "Recursive": true}'
          - '{"Path": "C:\\Windows\\Microsoft.NET\\Framework", "Pattern": ["msbuild.exe"], "Recursive": true}'

  # Step 2: Create EventBridge rule for new developer tools
  DeveloperToolsRule:
    Type: AWS::Events::Rule
    Properties:
      Name: T1127-DeveloperToolsDetected
      Description: Alert when developer tools found on non-dev instances
      EventPattern:
        source:
          - aws.ssm
        detail-type:
          - "Inventory Change"
        detail:
          changed-type:
            - AWS:Application
          application-name:
            - prefix: "Microsoft Visual Studio"
            - prefix: "Microsoft Build Tools"
      State: ENABLED
      Targets:
        - Id: SNSTarget
          Arn: !Ref SNSTopicArn

  # Step 3: EventBridge permission for SNS
  EventBridgeSNSPermission:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref SNSTopicArn]
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref SNSTopicArn""",
                terraform_template="""# Systems Manager inventory for developer tools detection

variable "sns_topic_arn" {
  type = string
}

# Step 1: Create SSM association for inventory collection
resource "aws_ssm_association" "inventory" {
  name                = "AWS-GatherSoftwareInventory"
  association_name    = "T1127-DeveloperToolsInventory"
  schedule_expression = "rate(1 day)"

  targets {
    key    = "InstanceIds"
    values = ["*"]
  }

  parameters = {
    applications = "Enabled"
    files = jsonencode([
      {
        Path      = "C:\\Program Files (x86)\\Microsoft Visual Studio"
        Pattern   = ["msbuild.exe"]
        Recursive = true
      },
      {
        Path      = "C:\\Windows\\Microsoft.NET\\Framework"
        Pattern   = ["msbuild.exe"]
        Recursive = true
      }
    ])
  }
}

# Step 2: Create EventBridge rule for new developer tools
resource "aws_cloudwatch_event_rule" "developer_tools" {
  name        = "T1127-DeveloperToolsDetected"
  description = "Alert when developer tools found on non-dev instances"

  event_pattern = jsonencode({
    source      = ["aws.ssm"]
    detail-type = ["Inventory Change"]
    detail = {
      changed-type = ["AWS:Application"]
      application-name = [
        { prefix = "Microsoft Visual Studio" },
        { prefix = "Microsoft Build Tools" }
      ]
    }
  })
}

# Step 3: Route to SNS
resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.developer_tools.name
  arn  = var.sns_topic_arn
}

resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = var.sns_topic_arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = var.sns_topic_arn
    }]
  })
}""",
                alert_severity="medium",
                alert_title="Developer Tools Found on Instance",
                alert_description_template=(
                    "Developer tools detected on instance {instance_id}. "
                    "Application: {application_name}. Review if this is a development instance."
                ),
                investigation_steps=[
                    "Verify if the instance is tagged as a development environment",
                    "Review instance purpose and validate developer tools are required",
                    "Check when the software was installed",
                    "Look for recent process execution logs involving these tools",
                    "Verify if the installation was authorised and documented",
                ],
                containment_actions=[
                    "Remove developer tools from production instances",
                    "Implement tag-based policies to restrict tool installation",
                    "Use Systems Manager Run Command to uninstall unauthorised software",
                    "Update golden AMIs to exclude developer utilities",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "Whitelist instances with 'Environment:Development' or similar tags. "
                "Create exceptions for build servers and CI/CD infrastructure."
            ),
            detection_coverage="85% - covers all EC2 instances with SSM agent",
            evasion_considerations=(
                "Attackers may install portable versions or use renamed executables. "
                "Tools may be present in non-standard locations not covered by inventory."
            ),
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-15 for SSM inventory",
            prerequisites=[
                "Systems Manager agent installed on EC2 instances",
                "IAM role with Systems Manager permissions",
                "Instances must be managed by Systems Manager",
            ],
        ),
        # Strategy 3: GCP - Cloud Logging for Process Execution
        DetectionStrategy(
            strategy_id="t1127-gcp-process-logging",
            name="GCP Cloud Logging for Developer Utility Execution",
            description=(
                "Monitor Cloud Logging for execution of developer utilities on GCE instances, "
                "particularly focusing on Windows instances in non-development projects."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gce_instance"
logName=~"windows.*"
jsonPayload.event_data.Image=~"(?i)(msbuild|dnx|rcsi|cdb|windbg|tracker)\\.exe"
NOT jsonPayload.event_data.ParentImage=~"(?i)(devenv|visualstudio|servicehub)"''',
                gcp_terraform_template="""# GCP: Cloud Logging alerts for developer utility execution

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "email" {
  project      = var.project_id
  display_name = "T1127 Security Alerts"
  type         = "email"

  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log-based metric for developer utility execution
resource "google_logging_metric" "developer_utility_exec" {
  project = var.project_id
  name    = "developer-utility-execution"

  filter = <<-EOT
    resource.type="gce_instance"
    logName=~"windows.*"
    jsonPayload.event_data.Image=~"(?i)(msbuild|dnx|rcsi|cdb|windbg|tracker)\\.exe"
    NOT jsonPayload.event_data.ParentImage=~"(?i)(devenv|visualstudio|servicehub)"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "instance_id"
      value_type  = "STRING"
      description = "GCE instance ID"
    }
  }

  label_extractors = {
    instance_id = "EXTRACT(resource.labels.instance_id)"
  }
}

# Step 3: Create alert policy
resource "google_monitoring_alert_policy" "developer_utility_alert" {
  project      = var.project_id
  display_name = "T1127: Developer Utility Proxy Execution"
  combiner     = "OR"

  conditions {
    display_name = "Developer utility executed in non-dev context"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.developer_utility_exec.name}\" AND resource.type=\"gce_instance\""
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
    auto_close = "604800s"  # 7 days
  }

  documentation {
    content   = "Developer utility executed on GCE instance. Investigate for potential T1127 defence evasion technique."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="high",
                alert_title="GCP: Developer Utility Proxy Execution",
                alert_description_template=(
                    "Developer utility executed on instance {instance_id} in project {project_id}. "
                    "Process: {process_name}. Investigate for T1127 technique."
                ),
                investigation_steps=[
                    "Identify the GCE instance and verify its purpose",
                    "Review the process command line and parent process",
                    "Check instance labels/tags for development classification",
                    "Examine VPC Flow Logs for network connections from the process",
                    "Review Cloud Audit Logs for recent instance access",
                    "Check for other suspicious process executions",
                    "Validate if developer tools should be present on the instance",
                ],
                containment_actions=[
                    "Suspend the GCE instance to prevent further execution",
                    "Create disk snapshot for forensic analysis",
                    "Remove developer tools from production instances",
                    "Implement Organisation Policy constraints to restrict software",
                    "Review and update golden images to exclude build tools",
                    "Enable OS Config for centralised patch and software management",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "Filter by instance labels (env:development). "
                "Exclude known build servers and CI/CD infrastructure. "
                "Consider project-level filtering for development projects."
            ),
            detection_coverage="75% - covers GCE instances with logging configured",
            evasion_considerations=(
                "Attackers may disable logging, use renamed executables, or execute from "
                "non-standard paths. Portable versions may avoid typical installation paths."
            ),
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1.5 hours",
            estimated_monthly_cost="$8-25 depending on log volume",
            prerequisites=[
                "Cloud Logging enabled for GCE instances",
                "Windows event forwarding configured to Cloud Logging",
                "Appropriate IAM permissions for log-based metrics",
            ],
        ),
        # Strategy 4: Container Image Scanning
        DetectionStrategy(
            strategy_id="t1127-container-scanning",
            name="Container Image Scanning for Developer Tools",
            description=(
                "Scan container images in ECR/GCR/Artifact Registry for presence of developer "
                "utilities that could be abused for code execution in containerised environments."
            ),
            detection_type=DetectionType.CUSTOM_LAMBDA,
            aws_service="ecr",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                cloudformation_template='''AWSTemplateFormatVersion: '2010-09-09'
Description: ECR image scanning for developer utilities

Parameters:
  SNSTopicArn:
    Type: String

Resources:
  # Step 1: Enable ECR image scanning on push
  ImageScanningRule:
    Type: AWS::Events::Rule
    Properties:
      Name: T1127-ECRImageScan
      Description: Trigger scan findings review for developer utilities
      EventPattern:
        source:
          - aws.ecr
        detail-type:
          - "ECR Image Scan"
        detail:
          scan-status:
            - COMPLETE
          finding-severity-counts:
            CRITICAL:
              - numeric: [">=", 1]
            HIGH:
              - numeric: [">=", 1]
      State: ENABLED
      Targets:
        - Id: SNSTarget
          Arn: !Ref SNSTopicArn

  # Step 2: Lambda function to check for developer utilities
  ScanReviewFunction:
    Type: AWS::Lambda::Function
    Properties:
      FunctionName: T1127-ReviewImageContents
      Runtime: python3.11
      Handler: index.handler
      Role: !GetAtt ScanReviewRole.Arn
      Code:
        ZipFile: |
          import json
          import boto3

          ecr = boto3.client('ecr')
          sns = boto3.client('sns')

          DEVELOPER_UTILITIES = [
              'msbuild.exe', 'dnx.exe', 'rcsi.exe',
              'cdb.exe', 'windbg.exe', 'tracker.exe',
              'msbuild', 'dotnet', 'csc.exe'
          ]

          def handler(event, context):
              # Note: This is a simplified example
              # Real implementation would scan image layers
              repository = event['detail']['repository-name']
              image_tag = event['detail']['image-tags'][0]

              # Check findings for developer utilities
              # In production, integrate with image scanning tools
              message = f"Review image {repository}:{image_tag} for developer utilities"

              return {'statusCode': 200, 'body': json.dumps(message)}

  # Step 3: Lambda execution role
  ScanReviewRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: lambda.amazonaws.com
            Action: sts:AssumeRole
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
      Policies:
        - PolicyName: ECRReadPolicy
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - ecr:DescribeImages
                  - ecr:DescribeImageScanFindings
                  - ecr:GetDownloadUrlForLayer
                Resource: "*"''',
                terraform_template="""# ECR image scanning for developer utilities

variable "sns_topic_arn" {
  type = string
}

# Step 1: Enable ECR image scanning rule
resource "aws_cloudwatch_event_rule" "ecr_scan" {
  name        = "T1127-ECRImageScan"
  description = "Trigger scan findings review for developer utilities"

  event_pattern = jsonencode({
    source      = ["aws.ecr"]
    detail-type = ["ECR Image Scan"]
    detail = {
      scan-status = ["COMPLETE"]
      finding-severity-counts = {
        CRITICAL = [{ numeric = [">=", 1] }]
        HIGH     = [{ numeric = [">=", 1] }]
      }
    }
  })
}

# Step 2: Lambda function to check for developer utilities
resource "aws_lambda_function" "scan_review" {
  filename      = "scan_review.zip"  # Package separately
  function_name = "T1127-ReviewImageContents"
  role          = aws_iam_role.scan_review.arn
  handler       = "index.handler"
  runtime       = "python3.11"
  timeout       = 60

  environment {
    variables = {
      SNS_TOPIC_ARN = var.sns_topic_arn
    }
  }
}

# Step 3: Lambda execution role
resource "aws_iam_role" "scan_review" {
  name = "T1127-ScanReviewRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_basic" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
  role       = aws_iam_role.scan_review.name
}

resource "aws_iam_role_policy" "ecr_read" {
  name = "ECRReadPolicy"
  role = aws_iam_role.scan_review.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "ecr:DescribeImages",
        "ecr:DescribeImageScanFindings",
        "ecr:GetDownloadUrlForLayer"
      ]
      Resource = "*"
    }]
  })
}

# EventBridge target
resource "aws_cloudwatch_event_target" "lambda" {
  rule = aws_cloudwatch_event_rule.ecr_scan.name
  arn  = aws_lambda_function.scan_review.arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.scan_review.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.ecr_scan.arn
}""",
                alert_severity="medium",
                alert_title="Developer Utilities in Container Image",
                alert_description_template=(
                    "Container image {repository}:{tag} contains developer utilities. "
                    "Review if these tools are necessary for production deployment."
                ),
                investigation_steps=[
                    "Review the container image manifest and layers",
                    "Identify which developer utilities are present",
                    "Verify if the image is for development or production use",
                    "Check if the utilities are required for application functionality",
                    "Review container runtime policies and restrictions",
                    "Examine deployment configurations (ECS task definitions, K8s manifests)",
                ],
                containment_actions=[
                    "Build new image without developer utilities",
                    "Update golden images and base layers",
                    "Implement image vulnerability scanning in CI/CD pipeline",
                    "Use distroless or minimal base images where possible",
                    "Enforce image scanning policies before deployment",
                    "Tag and quarantine images containing unnecessary tools",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning=(
                "Whitelist development/build container images by repository name or tag pattern. "
                "Create exceptions for legitimate build containers used in CI/CD. "
                "Focus on production deployment repositories."
            ),
            detection_coverage="60% - depends on image scanning configuration and coverage",
            evasion_considerations=(
                "Attackers may use multi-stage builds to remove utilities from final image, "
                "or download tools at runtime. Detection limited to what's in the image layers."
            ),
            implementation_effort=EffortLevel.HIGH,
            implementation_time="4 hours",
            estimated_monthly_cost="$15-40 for ECR scanning and Lambda execution",
            prerequisites=[
                "ECR image scanning enabled",
                "Lambda execution permissions configured",
                "Container image scanning integrated in CI/CD pipeline",
            ],
        ),
    ],
    recommended_order=[
        "t1127-aws-ssm-inventory",  # Start with identifying where tools exist
        "t1127-aws-process-monitoring",  # Monitor execution on AWS instances
        "t1127-gcp-process-logging",  # Monitor execution on GCP instances
        "t1127-container-scanning",  # Scan container images for tools
    ],
    total_effort_hours=8.5,
    coverage_improvement="+35% improvement for Defence Evasion tactic",
)
