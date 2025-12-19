# A13E Detection Coverage Validator - AWS Cross-Account Role
#
# This Terraform module creates an IAM role that allows A13E to scan your
# AWS account for security detections and map them to MITRE ATT&CK techniques.
#
# Usage:
#   module "a13e_scanner" {
#     source      = "./a13e-scanner"
#     external_id = "a13e-your-external-id-here"
#   }
#
# The role has READ-ONLY access to security services only.
# It CANNOT modify, delete, or access any data in your account.

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 4.0"
    }
  }
}

variable "external_id" {
  type        = string
  description = "The external ID provided by A13E for your account. This prevents confused deputy attacks."

  validation {
    condition     = can(regex("^a13e-[a-f0-9]+$", var.external_id))
    error_message = "External ID must be a valid A13E external ID (format: a13e-{hex})."
  }
}

variable "a13e_account_id" {
  type        = string
  default     = "123080274263"
  description = "A13E's AWS account ID that will assume this role."

  validation {
    condition     = can(regex("^\\d{12}$", var.a13e_account_id))
    error_message = "Must be a 12-digit AWS account ID."
  }
}

variable "role_name" {
  type        = string
  default     = "A13E-DetectionScanner"
  description = "Name for the IAM role. Must be unique in your account."
}

# IAM Role with trust policy
resource "aws_iam_role" "a13e_scanner" {
  name        = var.role_name
  description = "Allows A13E Detection Coverage Validator to scan security configurations."

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${var.a13e_account_id}:root"
        }
        Action = "sts:AssumeRole"
        Condition = {
          StringEquals = {
            "sts:ExternalId" = var.external_id
          }
        }
      }
    ]
  })

  max_session_duration = 3600  # 1 hour max

  tags = {
    Purpose   = "A13E-Detection-Scanning"
    ManagedBy = "A13E"
    CreatedBy = "Terraform"
  }
}

# IAM Policy with read-only security permissions
resource "aws_iam_role_policy" "a13e_scanner" {
  name = "${var.role_name}-Policy"
  role = aws_iam_role.a13e_scanner.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # CloudWatch Logs - for log-based detections
      {
        Sid    = "A13ECloudWatchLogsAccess"
        Effect = "Allow"
        Action = [
          "logs:DescribeLogGroups",
          "logs:DescribeMetricFilters",
          "logs:DescribeSubscriptionFilters"
        ]
        Resource = "*"
      },
      # CloudWatch Alarms - for metric-based detections
      {
        Sid    = "A13ECloudWatchAlarmsAccess"
        Effect = "Allow"
        Action = [
          "cloudwatch:DescribeAlarms",
          "cloudwatch:DescribeAlarmsForMetric"
        ]
        Resource = "*"
      },
      # EventBridge - for event-driven detections
      {
        Sid    = "A13EEventBridgeAccess"
        Effect = "Allow"
        Action = [
          "events:ListRules",
          "events:DescribeRule",
          "events:ListTargetsByRule",
          "events:ListEventBuses"
        ]
        Resource = "*"
      },
      # GuardDuty - for threat detection
      {
        Sid    = "A13EGuardDutyAccess"
        Effect = "Allow"
        Action = [
          "guardduty:ListDetectors",
          "guardduty:GetDetector",
          "guardduty:ListFindings",
          "guardduty:GetFindings",
          "guardduty:GetFindingsStatistics"
        ]
        Resource = "*"
      },
      # Security Hub - for security standards
      {
        Sid    = "A13ESecurityHubAccess"
        Effect = "Allow"
        Action = [
          "securityhub:DescribeHub",
          "securityhub:GetEnabledStandards",
          "securityhub:DescribeStandards",
          "securityhub:DescribeStandardsControls",
          "securityhub:GetInsights",
          "securityhub:ListEnabledProductsForImport"
        ]
        Resource = "*"
      },
      # AWS Config - for compliance rules
      {
        Sid    = "A13EConfigAccess"
        Effect = "Allow"
        Action = [
          "config:DescribeConfigRules",
          "config:DescribeComplianceByConfigRule",
          "config:DescribeConfigRuleEvaluationStatus",
          "config:DescribeConformancePacks",
          "config:DescribeConformancePackCompliance"
        ]
        Resource = "*"
      },
      # CloudTrail - for audit logging configuration
      {
        Sid    = "A13ECloudTrailAccess"
        Effect = "Allow"
        Action = [
          "cloudtrail:DescribeTrails",
          "cloudtrail:GetTrailStatus",
          "cloudtrail:GetEventSelectors",
          "cloudtrail:ListTrails"
        ]
        Resource = "*"
      },
      # Lambda - for custom detection functions
      {
        Sid    = "A13ELambdaAccess"
        Effect = "Allow"
        Action = [
          "lambda:ListFunctions",
          "lambda:ListEventSourceMappings",
          "lambda:GetFunction",
          "lambda:GetFunctionConfiguration",
          "lambda:ListTags"
        ]
        Resource = "*"
      }
    ]
  })
}

# Outputs
output "role_arn" {
  description = "The ARN of the IAM role. Copy this value and paste it into A13E when connecting your AWS account."
  value       = aws_iam_role.a13e_scanner.arn
}

output "role_name" {
  description = "The name of the created IAM role."
  value       = aws_iam_role.a13e_scanner.name
}

output "external_id" {
  description = "The external ID used for this role."
  value       = var.external_id
  sensitive   = true
}
