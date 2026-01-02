"""
T1648 - Serverless Execution

Adversaries use serverless functions (Lambda, Cloud Functions) to execute
arbitrary code. Can be used for cryptomining, privilege escalation, or backdoors.
Used by Pacu, SCARLETEEL, and various cryptomining campaigns.
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
    technique_id="T1648",
    technique_name="Serverless Execution",
    tactic_ids=["TA0002"],
    mitre_url="https://attack.mitre.org/techniques/T1648/",
    threat_context=ThreatContext(
        description=(
            "Adversaries exploit serverless computing services (Lambda, Cloud Functions) "
            "to execute arbitrary code. Used for cryptomining, privilege escalation "
            "through IAM roles, or persistent backdoors triggered by events."
        ),
        attacker_goal="Execute malicious code via serverless functions",
        why_technique=[
            "Serverless has IAM roles with permissions",
            "Event-triggered execution for persistence",
            "Can add credentials to new users",
            "Abuse automation for lateral movement",
            "Hard to detect among legitimate functions",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="moderate",
        trend="increasing",
        severity_score=7,
        severity_reasoning=(
            "Serverless functions can have powerful IAM roles. "
            "Event-triggered functions provide persistence. "
            "Difficult to detect among many legitimate functions."
        ),
        business_impact=[
            "Arbitrary code execution",
            "Privilege escalation via function roles",
            "Persistent backdoors",
            "Resource abuse (cryptomining)",
        ],
        typical_attack_phase="execution",
        often_precedes=["T1098.001", "T1530"],
        often_follows=["T1078.004", "T1098.003"],
    ),
    detection_strategies=[
        # =====================================================================
        # STRATEGY 1: GuardDuty Lambda Protection (Recommended)
        # =====================================================================
        DetectionStrategy(
            strategy_id="t1648-aws-guardduty-lambda",
            name="AWS GuardDuty Lambda Protection",
            description=(
                "Leverage GuardDuty Lambda Protection for runtime threat detection. "
                "Detects cryptomining, C&C communication, and malicious network activity. "
                "See: https://docs.aws.amazon.com/guardduty/latest/ug/lambda-protection-finding-types.html"
            ),
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "CryptoCurrency:Lambda/BitcoinTool.B",
                    "Backdoor:Lambda/C&CActivity.B",
                    "Trojan:Lambda/BlackholeTraffic",
                    "Trojan:Lambda/DropPoint",
                    "UnauthorizedAccess:Lambda/MaliciousIPCaller.Custom",
                    "UnauthorizedAccess:Lambda/TorClient",
                    "UnauthorizedAccess:Lambda/TorRelay",
                ],
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: |
  GuardDuty Lambda Protection
  Detects: CryptoCurrency:Lambda/BitcoinTool.B, Backdoor:Lambda/C&CActivity.B
  See: https://docs.aws.amazon.com/guardduty/latest/ug/lambda-protection-finding-types.html

Parameters:
  AlertEmail:
    Type: String
    Description: Email for Lambda security alerts

Resources:
  # SNS Topic for Lambda findings
  LambdaAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      TopicName: guardduty-lambda-alerts
      KmsMasterKeyId: alias/aws/sns

  AlertSubscription:
    Type: AWS::SNS::Subscription
    Properties:
      TopicArn: !Ref LambdaAlertTopic
      Protocol: email
      Endpoint: !Ref AlertEmail

  # EventBridge rule for Lambda findings
  LambdaFindingRule:
    Type: AWS::Events::Rule
    Properties:
      Name: guardduty-lambda-findings
      Description: Detect Lambda-related GuardDuty findings
      State: ENABLED
      EventPattern:
        source:
          - aws.guardduty
        detail-type:
          - GuardDuty Finding
        detail:
          type:
            - prefix: "CryptoCurrency:Lambda/"
            - prefix: "Backdoor:Lambda/"
            - prefix: "Trojan:Lambda/"
            - prefix: "UnauthorizedAccess:Lambda/"
      Targets:
        - Id: SendToSNS
          Arn: !Ref LambdaAlertTopic
          InputTransformer:
            InputPathsMap:
              findingType: $.detail.type
              severity: $.detail.severity
              functionArn: $.detail.resource.lambdaDetails.functionArn
              functionName: $.detail.resource.lambdaDetails.functionName
              accountId: $.account
            InputTemplate: |
              "CRITICAL: GuardDuty Lambda Finding"
              "Type: <findingType>"
              "Severity: <severity>"
              "Function: <functionName>"
              "ARN: <functionArn>"
              "Account: <accountId>"
              "Action: Immediately investigate this Lambda function"

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref LambdaAlertTopic
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref LambdaAlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn: !GetAtt LambdaFindingRule.Arn

  # Enable GuardDuty with Lambda Protection
  GuardDutyDetector:
    Type: AWS::GuardDuty::Detector
    Properties:
      Enable: true
      Features:
        - Name: LAMBDA_NETWORK_LOGS
          Status: ENABLED

Outputs:
  AlertTopicArn:
    Description: SNS topic for Lambda alerts
    Value: !Ref LambdaAlertTopic""",
                terraform_template="""# AWS GuardDuty Lambda Protection
# Detects: CryptoCurrency:Lambda/BitcoinTool.B, Backdoor:Lambda/C&CActivity.B
# See: https://docs.aws.amazon.com/guardduty/latest/ug/lambda-protection-finding-types.html

variable "alert_email" {
  type        = string
  description = "Email for Lambda security alerts"
}

# Step 1: Create encrypted SNS topic
resource "aws_sns_topic" "lambda_alerts" {
  name              = "guardduty-lambda-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "alert_email" {
  topic_arn = aws_sns_topic.lambda_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Enable GuardDuty with Lambda Protection
resource "aws_guardduty_detector" "main" {
  enable = true

  datasources {
    s3_logs {
      enable = true
    }
  }
}

resource "aws_guardduty_detector_feature" "lambda_protection" {
  detector_id = aws_guardduty_detector.main.id
  name        = "LAMBDA_NETWORK_LOGS"
  status      = "ENABLED"
}

# Step 3: Route Lambda findings to SNS
resource "aws_cloudwatch_event_rule" "lambda_findings" {
  name        = "guardduty-lambda-findings"
  description = "Detect Lambda-related GuardDuty findings"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [
        { prefix = "CryptoCurrency:Lambda/" },
        { prefix = "Backdoor:Lambda/" },
        { prefix = "Trojan:Lambda/" },
        { prefix = "UnauthorizedAccess:Lambda/" }
      ]
    }
  })
}

resource "aws_sqs_queue" "lambda_dlq" {
  name                      = "guardduty-lambda-dlq"
  message_retention_seconds = 1209600  # 14 days
}

resource "aws_sqs_queue_policy" "lambda_dlq_policy" {
  queue_url = aws_sqs_queue.lambda_dlq.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.lambda_dlq.arn
      Condition = {
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.lambda_findings.arn
        }
      }
    }]
  })
}

resource "aws_cloudwatch_event_target" "to_sns" {
  rule      = aws_cloudwatch_event_rule.lambda_findings.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.lambda_alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.lambda_dlq.arn
  }

  input_transformer {
    input_paths = {
      findingType  = "$.detail.type"
      severity     = "$.detail.severity"
      functionArn  = "$.detail.resource.lambdaDetails.functionArn"
      functionName = "$.detail.resource.lambdaDetails.functionName"
      accountId    = "$.account"
    }
    input_template = <<-EOF
      "CRITICAL: GuardDuty Lambda Finding"
      "Type: <findingType>"
      "Severity: <severity>"
      "Function: <functionName>"
      "ARN: <functionArn>"
      "Account: <accountId>"
      "Action: Immediately investigate this Lambda function"
    EOF
  }
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.lambda_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowEventBridgePublish"
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.lambda_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.lambda_findings.arn
        }
      }
    }]
  })
}""",
                alert_severity="critical",
                alert_title="GuardDuty: Malicious Lambda Activity Detected",
                alert_description_template=(
                    "GuardDuty has detected malicious activity from Lambda function {functionName}: {type}. "
                    "This may indicate cryptomining, backdoor, or C&C communication."
                ),
                investigation_steps=[
                    "Review the specific GuardDuty finding in the console",
                    "Examine the Lambda function code for malicious content",
                    "Check the function's execution logs in CloudWatch",
                    "Review the IAM role attached to the function",
                    "Identify who created or modified the function",
                ],
                containment_actions=[
                    "Immediately disable or delete the malicious function",
                    "Revoke the function's IAM role permissions",
                    "Review and rotate any credentials the function had access to",
                    "Check for other functions created by the same principal",
                    "Block the function's network destinations in VPC/WAF",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning=(
                "GuardDuty Lambda findings have low false positives. "
                "Suppress findings for legitimate blockchain/crypto applications. "
                "Use suppression rules with function name filters."
            ),
            detection_coverage="90% - runtime network activity monitoring",
            evasion_considerations=(
                "Functions not using VPC may have limited monitoring. "
                "Obfuscated or encrypted C&C traffic may evade."
            ),
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost=(
                "Lambda Protection: $1.50 per million function invocations. "
                "See: https://aws.amazon.com/guardduty/pricing/"
            ),
            prerequisites=[
                "GuardDuty enabled",
                "Lambda functions using VPC (recommended)",
            ],
        ),
        # =====================================================================
        # STRATEGY 2: Lambda Function Lifecycle Monitoring
        # =====================================================================
        DetectionStrategy(
            strategy_id="t1648-aws-lambda-lifecycle",
            name="Lambda Function Lifecycle Monitoring",
            description=(
                "Monitor Lambda function creation, updates, and permission changes. "
                "Detect unauthorised function deployments and suspicious IAM role attachments."
            ),
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="lambda",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.lambda"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventName": [
                            "CreateFunction20150331",
                            "UpdateFunctionCode20150331v2",
                            "UpdateFunctionConfiguration20150331v2",
                            "AddPermission20150331v2",
                            "CreateEventSourceMapping",
                        ]
                    },
                },
                terraform_template="""# Lambda Function Lifecycle Monitoring
# Monitors creation, updates, and permission changes

variable "alert_email" {
  type        = string
  description = "Email for Lambda lifecycle alerts"
}

variable "allowed_deployers" {
  type        = list(string)
  default     = []
  description = "IAM ARNs allowed to deploy Lambda functions"
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "lambda_lifecycle" {
  name              = "lambda-lifecycle-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.lambda_lifecycle.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_sqs_queue" "lifecycle_dlq" {
  name                      = "lambda-lifecycle-dlq"
  message_retention_seconds = 1209600  # 14 days
}

resource "aws_sqs_queue_policy" "lifecycle_dlq_policy" {
  queue_url = aws_sqs_queue.lifecycle_dlq.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.lifecycle_dlq.arn
      Condition = {
        ArnEquals = {
          "aws:SourceArn" = [
            aws_cloudwatch_event_rule.lambda_create.arn,
            aws_cloudwatch_event_rule.lambda_update.arn,
            aws_cloudwatch_event_rule.lambda_permission.arn
          ]
        }
      }
    }]
  })
}

# Step 2: EventBridge rule for function creation
resource "aws_cloudwatch_event_rule" "lambda_create" {
  name        = "lambda-function-creation"
  description = "Detect new Lambda function creation"

  event_pattern = jsonencode({
    source      = ["aws.lambda"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["CreateFunction20150331"]
    }
  })
}

resource "aws_cloudwatch_event_target" "create_to_sns" {
  rule      = aws_cloudwatch_event_rule.lambda_create.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.lambda_lifecycle.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.lifecycle_dlq.arn
  }

  input_transformer {
    input_paths = {
      functionName = "$.detail.requestParameters.functionName"
      runtime      = "$.detail.requestParameters.runtime"
      role         = "$.detail.requestParameters.role"
      user         = "$.detail.userIdentity.arn"
      sourceIp     = "$.detail.sourceIPAddress"
    }
    input_template = <<-EOF
      {
        "alert": "Lambda Function Created",
        "function": "<functionName>",
        "runtime": "<runtime>",
        "iamRole": "<role>",
        "createdBy": "<user>",
        "sourceIp": "<sourceIp>",
        "action": "Verify this function creation was authorised"
      }
    EOF
  }
}

# Step 3: EventBridge rule for code updates
resource "aws_cloudwatch_event_rule" "lambda_update" {
  name        = "lambda-code-update"
  description = "Detect Lambda function code updates"

  event_pattern = jsonencode({
    source      = ["aws.lambda"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["UpdateFunctionCode20150331v2"]
    }
  })
}

resource "aws_cloudwatch_event_target" "update_to_sns" {
  rule      = aws_cloudwatch_event_rule.lambda_update.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.lambda_lifecycle.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.lifecycle_dlq.arn
  }

  input_transformer {
    input_paths = {
      functionName = "$.detail.requestParameters.functionName"
      user         = "$.detail.userIdentity.arn"
      sourceIp     = "$.detail.sourceIPAddress"
    }
    input_template = <<-EOF
      {
        "alert": "Lambda Function Code Updated",
        "function": "<functionName>",
        "updatedBy": "<user>",
        "sourceIp": "<sourceIp>",
        "action": "Review the code changes for malicious content"
      }
    EOF
  }
}

# Step 4: EventBridge rule for permission additions (persistence)
resource "aws_cloudwatch_event_rule" "lambda_permission" {
  name        = "lambda-permission-added"
  description = "Detect Lambda permission additions"

  event_pattern = jsonencode({
    source      = ["aws.lambda"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["AddPermission20150331v2"]
    }
  })
}

resource "aws_cloudwatch_event_target" "permission_to_sns" {
  rule      = aws_cloudwatch_event_rule.lambda_permission.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.lambda_lifecycle.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.lifecycle_dlq.arn
  }

  input_transformer {
    input_paths = {
      functionName = "$.detail.requestParameters.functionName"
      principal    = "$.detail.requestParameters.principal"
      action       = "$.detail.requestParameters.action"
      user         = "$.detail.userIdentity.arn"
    }
    input_template = <<-EOF
      {
        "alert": "Lambda Permission Added",
        "severity": "HIGH",
        "function": "<functionName>",
        "allowedPrincipal": "<principal>",
        "allowedAction": "<action>",
        "addedBy": "<user>",
        "action": "Verify this permission grant - could enable external invocation"
      }
    EOF
  }
}

resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.lambda_lifecycle.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowEventBridgePublish"
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.lambda_lifecycle.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
        ArnEquals = {
          "aws:SourceArn" = [
            aws_cloudwatch_event_rule.lambda_create.arn,
            aws_cloudwatch_event_rule.lambda_update.arn,
            aws_cloudwatch_event_rule.lambda_permission.arn
          ]
        }
      }
    }]
  })
}

output "alert_topic_arn" {
  value       = aws_sns_topic.lambda_lifecycle.arn
  description = "SNS topic for Lambda lifecycle alerts"
}""",
                alert_severity="medium",
                alert_title="Lambda Function Lifecycle Event",
                alert_description_template=(
                    "Lambda function {functionName} was {eventName} by {userIdentity.arn}. "
                    "Verify this change was authorised."
                ),
                investigation_steps=[
                    "Verify the function creation/update was authorised",
                    "Review the function code for malicious content",
                    "Check the IAM role attached to the function",
                    "Review any event triggers configured",
                    "Check if the principal is a known CI/CD system",
                ],
                containment_actions=[
                    "Delete unauthorised functions immediately",
                    "Remove suspicious permissions from legitimate functions",
                    "Review and restrict Lambda deployment IAM policies",
                    "Enable Lambda code signing for trusted deployments",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "Filter out known CI/CD deployment pipelines by IAM ARN. "
                "Use Lambda code signing to allow only trusted deployments. "
                "Consider separate alerting for production vs non-production."
            ),
            detection_coverage="95% - catches all function lifecycle events",
            evasion_considerations="Cannot evade CloudTrail logging of API calls",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10/month (EventBridge + SNS)",
            prerequisites=["CloudTrail enabled"],
        ),
        # =====================================================================
        # STRATEGY 3: Lambda IAM Role Privilege Analysis
        # =====================================================================
        DetectionStrategy(
            strategy_id="t1648-aws-lambda-iam",
            name="Lambda IAM Role Privilege Analysis",
            description=(
                "Detect Lambda functions with overly permissive IAM roles. "
                "Functions with admin privileges or sensitive permissions are high-risk targets."
            ),
            detection_type=DetectionType.CONFIG_RULE,
            aws_service="config",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                config_rule_identifier="LAMBDA_FUNCTION_SETTINGS_CHECK",
                terraform_template="""# Lambda IAM Role Privilege Analysis
# Detects functions with overly permissive roles

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = ">= 2.4.0"
    }
  }
}

variable "alert_email" {
  type        = string
  description = "Email for privilege alerts"
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "lambda_iam_alerts" {
  name              = "lambda-iam-privilege-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.lambda_iam_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Config rule for Lambda function settings
resource "aws_config_config_rule" "lambda_settings" {
  name        = "lambda-function-settings-check"
  description = "Check Lambda function configuration settings"

  source {
    owner             = "AWS"
    source_identifier = "LAMBDA_FUNCTION_SETTINGS_CHECK"
  }

  input_parameters = jsonencode({
    runtime = "python3.11,python3.10,nodejs18.x,nodejs20.x"
  })

  depends_on = [aws_config_configuration_recorder.main]
}

# Step 3: Custom Config rule for admin role detection
resource "aws_config_config_rule" "lambda_admin_role" {
  name        = "lambda-no-admin-role"
  description = "Check Lambda functions do not use admin IAM roles"

  source {
    owner             = "CUSTOM_LAMBDA"
    source_identifier = aws_lambda_function.config_rule.arn

    source_detail {
      event_source = "aws.config"
      message_type = "ConfigurationItemChangeNotification"
    }
  }

  scope {
    compliance_resource_types = ["AWS::Lambda::Function"]
  }

  depends_on = [aws_config_configuration_recorder.main]
}

# Lambda function for custom Config rule
resource "aws_lambda_function" "config_rule" {
  function_name = "config-lambda-admin-role-check"
  runtime       = "python3.11"
  handler       = "index.handler"
  role          = aws_iam_role.config_lambda_role.arn
  timeout       = 60

  filename         = data.archive_file.config_lambda.output_path
  source_code_hash = data.archive_file.config_lambda.output_base64sha256
}

data "archive_file" "config_lambda" {
  type        = "zip"
  output_path = "${path.module}/config_lambda.zip"

  source {
    content  = <<-PYTHON
import boto3
import json

iam = boto3.client('iam')
config = boto3.client('config')

ADMIN_POLICIES = [
    'arn:aws:iam::aws:policy/AdministratorAccess',
    'arn:aws:iam::aws:policy/IAMFullAccess',
    'arn:aws:iam::aws:policy/PowerUserAccess'
]


def handler(event, context):
    invoking_event = json.loads(event['invokingEvent'])
    configuration_item = invoking_event['configurationItem']

    if configuration_item['resourceType'] != 'AWS::Lambda::Function':
        return

    compliance_type = 'COMPLIANT'
    annotation = 'Lambda function has appropriate IAM permissions'

    # Get the function's IAM role
    role_arn = configuration_item['configuration'].get('role', '')
    if not role_arn:
        compliance_type = 'NON_COMPLIANT'
        annotation = 'Lambda function has no IAM role configured'
    else:
        role_name = role_arn.split('/')[-1]
        # Check attached policies
        try:
            attached = iam.list_attached_role_policies(RoleName=role_name)
            for policy in attached.get('AttachedPolicies', []):
                if policy['PolicyArn'] in ADMIN_POLICIES:
                    compliance_type = 'NON_COMPLIANT'
                    annotation = f"Lambda has admin policy: {policy['PolicyName']}"
                    break
        except Exception as e:
            annotation = f"Could not check role policies: {str(e)}"

    config.put_evaluations(
        Evaluations=[{
            'ComplianceResourceType': configuration_item['resourceType'],
            'ComplianceResourceId': configuration_item['resourceId'],
            'ComplianceType': compliance_type,
            'Annotation': annotation,
            'OrderingTimestamp': configuration_item['configurationItemCaptureTime']
        }],
        ResultToken=event['resultToken']
    )
PYTHON
    filename = "index.py"
  }
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

resource "aws_iam_role" "config_lambda_role" {
  name = "config-lambda-admin-check-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Condition = {
        StringEquals = {
          "aws:SourceAccount" = data.aws_caller_identity.current.account_id
        }
        ArnLike = {
          "aws:SourceArn" = "arn:aws:lambda:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:function:*"
        }
      }
    }]
  })
}

resource "aws_iam_role_policy" "config_lambda_policy" {
  name = "config-lambda-policy"
  role = aws_iam_role.config_lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect   = "Allow"
        Action   = ["iam:ListAttachedRolePolicies", "iam:ListRolePolicies", "iam:GetRolePolicy"]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["config:PutEvaluations"]
        Resource = "*"
      }
    ]
  })
}

resource "aws_lambda_permission" "config_permission" {
  statement_id  = "AllowConfigInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.config_rule.function_name
  principal     = "config.amazonaws.com"
}

# Config recorder (if not exists)
resource "aws_config_configuration_recorder" "main" {
  name     = "default"
  role_arn = aws_iam_role.config_role.arn

  recording_group {
    all_supported = true
  }
}

resource "aws_iam_role" "config_role" {
  name = "config-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "config.amazonaws.com" }
      Condition = {
        StringEquals = {
          "aws:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "config_policy" {
  role       = aws_iam_role.config_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}""",
                alert_severity="high",
                alert_title="Lambda Function with Excessive Privileges",
                alert_description_template=(
                    "Lambda function {functionName} has overly permissive IAM role. "
                    "Functions with admin access are high-risk targets for attackers."
                ),
                investigation_steps=[
                    "Review the Lambda function's IAM role and policies",
                    "Identify what permissions the function actually needs",
                    "Check if the function was recently modified",
                    "Review the function's execution history",
                ],
                containment_actions=[
                    "Apply least-privilege IAM policy to the function",
                    "Remove admin or overly permissive policies",
                    "Use resource-based policies where possible",
                    "Enable Lambda code signing",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "Some functions legitimately need broad permissions. "
                "Use resource exceptions for authorised admin functions. "
                "Consider different thresholds for dev vs production."
            ),
            detection_coverage="80% - continuous compliance checking",
            evasion_considerations="Inline policies may not be fully checked",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$10-20/month (Config + Lambda)",
            prerequisites=["AWS Config enabled"],
        ),
        # =====================================================================
        # STRATEGY 4: GCP Cloud Functions Detection
        # =====================================================================
        DetectionStrategy(
            strategy_id="t1648-gcp-functions",
            name="GCP Cloud Functions Creation and Invocation Detection",
            description=(
                "Monitor Cloud Functions creation, updates, and unusual invocation patterns. "
                "Detect unauthorised function deployments and potential abuse."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""# Cloud Functions lifecycle events
protoPayload.serviceName="cloudfunctions.googleapis.com"
protoPayload.methodName=~"CreateFunction|UpdateFunction|DeleteFunction"

# Cloud Functions invocations (for anomaly detection)
resource.type="cloud_function"
textPayload:*""",
                gcp_terraform_template="""# GCP Cloud Functions Detection

variable "project_id" {
  type        = string
  description = "GCP Project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "email_s1" {
  display_name = "Cloud Functions Security Alerts"
  type         = "email"
  project      = var.project_id

  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for function creation
resource "google_logging_metric" "function_create" {
  name    = "cloud-functions-creation"
  project = var.project_id

  filter = <<-EOT
    protoPayload.serviceName="cloudfunctions.googleapis.com"
    protoPayload.methodName=~"CreateFunction|v2.FunctionService.CreateFunction"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
    labels {
      key         = "principal"
      value_type  = "STRING"
      description = "Principal creating function"
    }
    labels {
      key         = "function_name"
      value_type  = "STRING"
      description = "Function name"
    }
  }

  label_extractors = {
    "principal"     = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
    "function_name" = "EXTRACT(protoPayload.resourceName)"
  }
}

# Step 3: Alert on function creation
resource "google_monitoring_alert_policy" "function_create" {
  project      = var.project_id
  display_name = "Cloud Function Created"
  combiner     = "OR"

  conditions {
    display_name = "Function creation detected"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.function_create.name}\" resource.type=\"global\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_COUNT"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email_s1.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }

  documentation {
    content   = "A Cloud Function was created. Verify this deployment was authorised and review the function code."
    mime_type = "text/markdown"
  }
}

# Step 4: Log-based metric for function updates
resource "google_logging_metric" "function_update" {
  name    = "cloud-functions-updates"
  project = var.project_id

  filter = <<-EOT
    protoPayload.serviceName="cloudfunctions.googleapis.com"
    protoPayload.methodName=~"UpdateFunction|v2.FunctionService.UpdateFunction"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
  }
}

resource "google_monitoring_alert_policy" "function_update" {
  project      = var.project_id
  display_name = "Cloud Function Updated"
  combiner     = "OR"

  conditions {
    display_name = "Function update detected"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.function_update.name}\" resource.type=\"global\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_COUNT"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email_s1.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }

  documentation {
    content   = "A Cloud Function was updated. Review the code changes for malicious content."
    mime_type = "text/markdown"
  }
}

# Step 5: Detect IAM permission grants to functions
resource "google_logging_metric" "function_iam" {
  name    = "cloud-functions-iam-changes"
  project = var.project_id

  filter = <<-EOT
    protoPayload.serviceName="cloudfunctions.googleapis.com"
    protoPayload.methodName="SetIamPolicy"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
  }
}

resource "google_monitoring_alert_policy" "function_iam" {
  project      = var.project_id
  display_name = "Cloud Function IAM Policy Changed"
  combiner     = "OR"

  conditions {
    display_name = "Function IAM change detected"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.function_iam.name}\" resource.type=\"global\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_COUNT"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email_s1.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }

  documentation {
    content   = "A Cloud Function's IAM policy was changed. Verify the permission grant was authorised."
    mime_type = "text/markdown"
  }
}

output "notification_channel_id" {
  value       = google_monitoring_notification_channel.email_s1.id
  description = "Notification channel for alerts"
}""",
                alert_severity="medium",
                alert_title="GCP: Cloud Function Lifecycle Event",
                alert_description_template=(
                    "Cloud Function {function_name} was created/updated by {principal}. "
                    "Verify this deployment was authorised."
                ),
                investigation_steps=[
                    "Verify the function creation/update was authorised",
                    "Review the function source code",
                    "Check the service account attached to the function",
                    "Review any event triggers (Pub/Sub, HTTP, etc.)",
                    "Check the principal's recent activity",
                ],
                containment_actions=[
                    "Delete unauthorised functions",
                    "Remove suspicious IAM bindings",
                    "Review service account permissions",
                    "Enable VPC Service Controls for Cloud Functions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "Filter out known CI/CD service accounts. "
                "Use separate alerting for production vs development. "
                "Consider Cloud Build integration for authorised deployments."
            ),
            detection_coverage="90% - catches all function lifecycle events",
            evasion_considerations="Cannot evade Cloud Audit Logs",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20/month (Logging + Monitoring)",
            prerequisites=[
                "Cloud Audit Logs enabled",
                "Data Access logs enabled for Cloud Functions",
            ],
        ),
    ],
    recommended_order=[
        "t1648-aws-guardduty-lambda",
        "t1648-aws-lambda-lifecycle",
        "t1648-aws-lambda-iam",
        "t1648-gcp-functions",
    ],
    total_effort_hours=6.0,
    coverage_improvement="+25% improvement for Execution tactic with multi-layered detection",
)
