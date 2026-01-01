# A13E Google Workspace WIF - Separate Terraform State
#
# This manages GCP Workload Identity Federation for Google Workspace access.
# Kept separate from main infrastructure because:
# - Requires GCP credentials (not available in GitHub Actions CI)
# - Rarely changes after initial setup
# - Internal tooling only (not customer-facing)
#
# Run locally with: gcloud auth application-default login

terraform {
  required_version = ">= 1.0.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 4.0.0"
    }
    aws = {
      source  = "hashicorp/aws"
      version = ">= 4.0.0"
    }
  }

  # Separate state file - stored locally or in S3 if needed
  backend "local" {
    path = "terraform.tfstate"
  }
}

provider "aws" {
  region = var.aws_region
}

provider "google" {
  project = var.gcp_project_id
  region  = "europe-west2"
}

# -----------------------------------------------------------------------------
# Variables
# -----------------------------------------------------------------------------

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "eu-west-2"
}

variable "aws_account_id" {
  description = "AWS account ID"
  type        = string
}

variable "environment" {
  description = "Environment (staging, production)"
  type        = string
  default     = "staging"
}

variable "gcp_project_id" {
  description = "GCP project ID for WIF"
  type        = string
}

variable "workspace_admin_email" {
  description = "Workspace admin email for domain-wide delegation"
  type        = string
}

variable "workspace_service_account_email" {
  description = "Existing GCP service account email"
  type        = string
}

# -----------------------------------------------------------------------------
# Module
# -----------------------------------------------------------------------------

module "workspace_wif" {
  source = "../terraform/modules/gcp-wif-workspace"

  gcp_project_id                 = var.gcp_project_id
  aws_account_id                 = var.aws_account_id
  aws_region                     = var.aws_region
  environment                    = var.environment
  workspace_domain               = "a13e.com"
  workspace_admin_email          = var.workspace_admin_email
  existing_service_account_email = var.workspace_service_account_email

  allowed_aws_roles = [
    "a13e-${var.environment}-ecs-task-role"
  ]
}

# -----------------------------------------------------------------------------
# Outputs
# -----------------------------------------------------------------------------

output "workload_identity_pool_id" {
  description = "WIF pool ID"
  value       = module.workspace_wif.workload_identity_pool_id
}

output "service_account_email" {
  description = "Service account email"
  value       = module.workspace_wif.service_account_email
}

output "configuration" {
  description = "Configuration for backend environment variables"
  value       = module.workspace_wif.configuration
}

output "domain_wide_delegation_instructions" {
  description = "Manual steps for domain-wide delegation"
  value       = module.workspace_wif.domain_wide_delegation_instructions
}
