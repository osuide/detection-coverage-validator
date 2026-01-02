# A13E Internal - Google Workspace Access via Workload Identity Federation
#
# This module configures WIF to allow a13e's AWS infrastructure to access
# Google Workspace APIs (Gmail, Drive, Sheets, etc.) without service account keys.
#
# Architecture:
#   AWS ECS Task → IAM Role → WIF → GCP Service Account → Workspace APIs
#                                          ↓
#                             Domain-Wide Delegation
#                                          ↓
#                             Impersonate Workspace User
#
# Benefits:
# - No service account keys to manage or rotate
# - Short-lived credentials (1 hour max)
# - Fine-grained attribute conditions
# - Audit trail in both AWS CloudTrail and GCP Cloud Audit Logs
#
# Prerequisites:
# - Domain-wide delegation must be manually enabled in Google Workspace Admin
# - Scopes must be manually granted in Admin Console → Security → API Controls

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
}

# -----------------------------------------------------------------
# Variables
# -----------------------------------------------------------------

variable "gcp_project_id" {
  description = "The GCP project ID where WIF will be configured (your internal project)"
  type        = string
}

variable "aws_account_id" {
  description = "A13E's AWS account ID"
  type        = string
}

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "eu-west-2"
}

variable "environment" {
  description = "Environment name (staging, production)"
  type        = string
  default     = "production"
}

variable "workspace_domain" {
  description = "Google Workspace domain"
  type        = string
  default     = "a13e.com"
}

variable "workspace_admin_email" {
  description = "Workspace admin email for impersonation (domain-wide delegation)"
  type        = string
  default     = "austin@a13e.com"
}

variable "allowed_aws_roles" {
  description = "List of AWS IAM role names allowed to federate"
  type        = list(string)
  default     = ["a13e-backend-task-role"]
}

variable "existing_service_account_email" {
  description = "Email of an existing service account to use (if empty, creates a new one)"
  type        = string
  default     = ""
}

# -----------------------------------------------------------------
# Enable Required GCP APIs
# -----------------------------------------------------------------

resource "google_project_service" "iam_credentials" {
  project            = var.gcp_project_id
  service            = "iamcredentials.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "sts" {
  project            = var.gcp_project_id
  service            = "sts.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "admin" {
  project            = var.gcp_project_id
  service            = "admin.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "gmail" {
  project            = var.gcp_project_id
  service            = "gmail.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "drive" {
  project            = var.gcp_project_id
  service            = "drive.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "sheets" {
  project            = var.gcp_project_id
  service            = "sheets.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "docs" {
  project            = var.gcp_project_id
  service            = "docs.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "calendar" {
  project            = var.gcp_project_id
  service            = "calendar-json.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "forms" {
  project            = var.gcp_project_id
  service            = "forms.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "groupssettings" {
  project            = var.gcp_project_id
  service            = "groupssettings.googleapis.com"
  disable_on_destroy = false
}

# -----------------------------------------------------------------
# Workload Identity Pool for A13E Internal
# -----------------------------------------------------------------

resource "google_iam_workload_identity_pool" "a13e_internal" {
  project                   = var.gcp_project_id
  workload_identity_pool_id = "a13e-internal-${var.environment}"
  display_name              = "A13E Internal (${var.environment})"
  description               = "Workload Identity Pool for A13E internal services accessing Google Workspace"
  disabled                  = false

  depends_on = [
    google_project_service.iam_credentials,
    google_project_service.sts,
  ]
}

# -----------------------------------------------------------------
# AWS OIDC Provider
# -----------------------------------------------------------------

resource "google_iam_workload_identity_pool_provider" "aws" {
  project                            = var.gcp_project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.a13e_internal.workload_identity_pool_id
  workload_identity_pool_provider_id = "aws-${var.environment}"
  display_name                       = "AWS Federation (${var.environment})"
  description                        = "AWS OIDC provider for A13E backend services"

  # AWS OIDC configuration
  aws {
    account_id = var.aws_account_id
  }

  # Attribute mapping
  # Note: extract pattern must NOT have leading slash
  # ARN format: arn:aws:sts::123:assumed-role/role-name/session
  attribute_mapping = {
    "google.subject"        = "assertion.arn"
    "attribute.aws_account" = "assertion.account"
    "attribute.aws_role"    = "assertion.arn.extract('assumed-role/{role}/')"
  }

  # Attribute condition - only allow specific AWS roles
  attribute_condition = join(" || ", [
    for role in var.allowed_aws_roles : "attribute.aws_role == '${role}'"
  ])
}

# -----------------------------------------------------------------
# Service Account for Workspace Access
# -----------------------------------------------------------------

# Use existing service account if provided
data "google_service_account" "existing" {
  count      = var.existing_service_account_email != "" ? 1 : 0
  account_id = var.existing_service_account_email
}

# Create new service account if not using existing
resource "google_service_account" "workspace_automation" {
  count        = var.existing_service_account_email == "" ? 1 : 0
  project      = var.gcp_project_id
  account_id   = "a13e-workspace-${var.environment}"
  display_name = "A13E Workspace Automation (${var.environment})"
  description  = "Service account for A13E to access Google Workspace APIs via domain-wide delegation"
}

locals {
  # Use existing SA if provided, otherwise use the created one
  service_account_email     = var.existing_service_account_email != "" ? var.existing_service_account_email : google_service_account.workspace_automation[0].email
  service_account_name      = var.existing_service_account_email != "" ? data.google_service_account.existing[0].name : google_service_account.workspace_automation[0].name
  service_account_unique_id = var.existing_service_account_email != "" ? data.google_service_account.existing[0].unique_id : google_service_account.workspace_automation[0].unique_id
}

# -----------------------------------------------------------------
# Allow WIF to Impersonate Service Account
# -----------------------------------------------------------------

resource "google_service_account_iam_member" "wif_impersonation" {
  for_each = toset(var.allowed_aws_roles)

  service_account_id = local.service_account_name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.a13e_internal.name}/attribute.aws_role/${each.value}"
}

# Token creator permission
resource "google_service_account_iam_member" "token_creator" {
  for_each = toset(var.allowed_aws_roles)

  service_account_id = local.service_account_name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.a13e_internal.name}/attribute.aws_role/${each.value}"
}

# -----------------------------------------------------------------
# Outputs
# -----------------------------------------------------------------

output "workload_identity_pool_id" {
  description = "The ID of the Workload Identity Pool"
  value       = google_iam_workload_identity_pool.a13e_internal.workload_identity_pool_id
}

output "workload_identity_pool_name" {
  description = "The full resource name of the Workload Identity Pool"
  value       = google_iam_workload_identity_pool.a13e_internal.name
}

output "provider_resource_name" {
  description = "Full resource name of the AWS provider (needed for credential configuration)"
  value       = google_iam_workload_identity_pool_provider.aws.name
}

output "service_account_email" {
  description = "Email of the service account for Workspace access"
  value       = local.service_account_email
}

output "service_account_unique_id" {
  description = "Unique ID of the service account (needed for domain-wide delegation)"
  value       = local.service_account_unique_id
}

output "configuration" {
  description = "Configuration values for the application"
  value = {
    gcp_project_id            = var.gcp_project_id
    pool_id                   = google_iam_workload_identity_pool.a13e_internal.workload_identity_pool_id
    provider_id               = google_iam_workload_identity_pool_provider.aws.workload_identity_pool_provider_id
    service_account_email     = local.service_account_email
    service_account_unique_id = local.service_account_unique_id
    workspace_admin_email     = var.workspace_admin_email
    pool_location             = "global"
  }
}

output "domain_wide_delegation_instructions" {
  description = "Manual steps required for domain-wide delegation"
  value       = <<-EOT

    ============================================================
    MANUAL STEPS REQUIRED - Domain-Wide Delegation
    ============================================================

    The following steps must be completed manually in Google Workspace Admin Console:

    1. Go to: admin.google.com
    2. Navigate to: Security → Access and data control → API controls
    3. Click: "Manage Domain Wide Delegation"
    4. Click: "Add new"
    5. Enter Client ID: ${local.service_account_unique_id}
    6. Add OAuth Scopes (comma-separated):

       https://www.googleapis.com/auth/admin.directory.group,
       https://www.googleapis.com/auth/admin.directory.group.member,
       https://www.googleapis.com/auth/gmail.labels,
       https://www.googleapis.com/auth/gmail.settings.basic,
       https://www.googleapis.com/auth/gmail.modify,
       https://www.googleapis.com/auth/drive,
       https://www.googleapis.com/auth/spreadsheets,
       https://www.googleapis.com/auth/documents,
       https://www.googleapis.com/auth/calendar,
       https://www.googleapis.com/auth/forms,
       https://www.googleapis.com/auth/groups

    7. Click "Authorize"

    ============================================================
    EOT
}
