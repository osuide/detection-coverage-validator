# A13E Detection Coverage Validator - AWS Terraform Module
#
# This module creates an IAM role with the minimum permissions required
# for A13E to scan your security detection configurations.
#
# Usage:
#   module "a13e_scanner" {
#     source      = "./a13e-aws"
#     external_id = "a13e-abc123..."  # Get from A13E dashboard
#   }
#
# Then copy the output role_arn to your A13E dashboard.

terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 4.0"
    }
  }
}

variable "a13e_account_id" {
  description = "A13E's AWS Account ID for cross-account access"
  type        = string
  default     = "123456789012"  # Replace with actual A13E account ID
}

variable "external_id" {
  description = "External ID from A13E dashboard (prevents confused deputy attacks)"
  type        = string

  validation {
    condition     = can(regex("^a13e-[a-f0-9]{32}$", var.external_id))
    error_message = "External ID must be in format: a13e-{32 hex characters}"
  }
}

variable "role_name" {
  description = "Name for the IAM role"
  type        = string
  default     = "A13E-DetectionScanner"
}

variable "tags" {
  description = "Tags to apply to resources"
  type        = map(string)
  default     = {}
}

locals {
  default_tags = {
    Application = "A13E"
    Purpose     = "DetectionCoverageScanning"
    ManagedBy   = "Terraform"
  }
  tags = merge(local.default_tags, var.tags)
}

# IAM Role for A13E cross-account access
resource "aws_iam_role" "a13e_scanner" {
  name        = var.role_name
  description = "Cross-account role for A13E Detection Coverage Validator. Read-only access to security configurations."

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

  max_session_duration = 3600  # 1 hour

  tags = local.tags
}

# IAM Policy with minimum required permissions
resource "aws_iam_role_policy" "a13e_scanner" {
  name = "${var.role_name}-Policy"
  role = aws_iam_role.a13e_scanner.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "CloudWatchLogsAccess"
        Effect = "Allow"
        Action = [
          "logs:DescribeLogGroups",
          "logs:DescribeMetricFilters",
          "logs:DescribeSubscriptionFilters"
        ]
        Resource = "*"
      },
      {
        Sid    = "CloudWatchAlarmsAccess"
        Effect = "Allow"
        Action = [
          "cloudwatch:DescribeAlarms",
          "cloudwatch:DescribeAlarmsForMetric"
        ]
        Resource = "*"
      },
      {
        Sid    = "EventBridgeAccess"
        Effect = "Allow"
        Action = [
          "events:ListRules",
          "events:DescribeRule",
          "events:ListTargetsByRule"
        ]
        Resource = "*"
      },
      {
        Sid    = "GuardDutyAccess"
        Effect = "Allow"
        Action = [
          "guardduty:ListDetectors",
          "guardduty:GetDetector",
          "guardduty:ListFindings",
          "guardduty:GetFindings"
        ]
        Resource = "*"
      },
      {
        Sid    = "SecurityHubAccess"
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
      {
        Sid    = "ConfigAccess"
        Effect = "Allow"
        Action = [
          "config:DescribeConfigRules",
          "config:DescribeComplianceByConfigRule"
        ]
        Resource = "*"
      },
      {
        Sid    = "CloudTrailAccess"
        Effect = "Allow"
        Action = [
          "cloudtrail:DescribeTrails",
          "cloudtrail:GetTrailStatus",
          "cloudtrail:GetEventSelectors"
        ]
        Resource = "*"
      },
      {
        Sid    = "LambdaAccess"
        Effect = "Allow"
        Action = [
          "lambda:ListFunctions",
          "lambda:ListEventSourceMappings",
          "lambda:GetFunction",
          "lambda:GetFunctionConfiguration"
        ]
        Resource = "*"
      }
    ]
  })
}

output "role_arn" {
  description = "ARN of the A13E scanner role - copy this to your A13E dashboard"
  value       = aws_iam_role.a13e_scanner.arn
}

output "role_name" {
  description = "Name of the IAM role"
  value       = aws_iam_role.a13e_scanner.name
}

output "external_id" {
  description = "External ID configured for the role"
  value       = var.external_id
  sensitive   = true
}
