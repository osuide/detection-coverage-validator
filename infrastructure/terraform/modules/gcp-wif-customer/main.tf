# A13E Detection Coverage Validator - GCP Workload Identity Federation Setup
#
# This Terraform module configures your GCP project to allow A13E to scan
# for security detections using Workload Identity Federation (WIF).
#
# WIF Benefits:
# - No service account keys to manage or rotate
# - Short-lived credentials (1 hour max)
# - Fine-grained attribute conditions
# - Audit trail in Cloud Audit Logs
#
# Usage:
#   module "a13e_wif" {
#     source              = "github.com/a13e/terraform-gcp-wif-customer"
#     project_id          = "your-gcp-project"
#     a13e_aws_account_id = "123080274263"  # A13E's AWS account ID
#   }

terraform {
  required_version = ">= 1.0.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 4.0.0"
    }
  }
}

# -----------------------------------------------------------------
# Variables
# -----------------------------------------------------------------

variable "project_id" {
  description = "The GCP project ID where WIF will be configured"
  type        = string
}

variable "a13e_aws_account_id" {
  description = "A13E's AWS account ID (shown in the A13E app during setup)"
  type        = string
  default     = "123080274263" # A13E's AWS account ID
}

variable "a13e_aws_role_name" {
  description = "Name of the IAM role A13E uses (provided by A13E)"
  type        = string
  default     = "A13E-Scanner-Role"
}

variable "pool_id" {
  description = "ID for the Workload Identity Pool"
  type        = string
  default     = "a13e-pool"
}

variable "provider_id" {
  description = "ID for the AWS provider within the pool"
  type        = string
  default     = "a13e-aws"
}

variable "service_account_id" {
  description = "ID for the service account A13E will impersonate"
  type        = string
  default     = "a13e-scanner"
}

# -----------------------------------------------------------------
# Enable Required APIs
# -----------------------------------------------------------------

resource "google_project_service" "iam_credentials" {
  project            = var.project_id
  service            = "iamcredentials.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "sts" {
  project            = var.project_id
  service            = "sts.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "cloudresourcemanager" {
  project            = var.project_id
  service            = "cloudresourcemanager.googleapis.com"
  disable_on_destroy = false
}

# -----------------------------------------------------------------
# Workload Identity Pool
# -----------------------------------------------------------------

resource "google_iam_workload_identity_pool" "a13e" {
  project                   = var.project_id
  workload_identity_pool_id = var.pool_id
  display_name              = "A13E Detection Scanner"
  description               = "Workload Identity Pool for A13E Detection Coverage Validator"
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
  project                            = var.project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.a13e.workload_identity_pool_id
  workload_identity_pool_provider_id = var.provider_id
  display_name                       = "AWS Federation"
  description                        = "AWS OIDC provider for A13E running on AWS ECS"

  # AWS OIDC configuration
  aws {
    account_id = var.a13e_aws_account_id
  }

  # Attribute mapping - maps AWS claims to Google attributes
  attribute_mapping = {
    "google.subject"        = "assertion.arn"
    "attribute.aws_account" = "assertion.account"
    "attribute.aws_role"    = "assertion.arn.extract('/assumed-role/{role}/')"
  }

  # Attribute condition - only allow specific AWS role
  # This ensures only A13E's scanner role can federate
  attribute_condition = "attribute.aws_role == '${var.a13e_aws_role_name}'"
}

# -----------------------------------------------------------------
# Service Account for A13E to Impersonate
# -----------------------------------------------------------------

resource "google_service_account" "a13e_scanner" {
  project      = var.project_id
  account_id   = var.service_account_id
  display_name = "A13E Detection Scanner"
  description  = "Service account for A13E Detection Coverage Validator. Read-only access to security configurations."
}

# -----------------------------------------------------------------
# Custom IAM Role with Minimum Permissions
# -----------------------------------------------------------------

resource "google_project_iam_custom_role" "a13e_scanner" {
  project     = var.project_id
  role_id     = "a13e_detection_scanner"
  title       = "A13E Detection Scanner"
  description = "Minimum read-only permissions for A13E to scan security detection configurations"
  stage       = "GA"

  permissions = [
    # Cloud Logging - for log-based metrics and sinks
    "logging.logMetrics.list",
    "logging.logMetrics.get",
    "logging.sinks.list",
    "logging.sinks.get",

    # Cloud Monitoring - for alerting policies
    "monitoring.alertPolicies.list",
    "monitoring.alertPolicies.get",
    "monitoring.notificationChannels.list",
    "monitoring.notificationChannels.get",

    # Security Command Center - for findings
    "securitycenter.findings.list",
    "securitycenter.findings.get",
    "securitycenter.sources.list",
    "securitycenter.sources.get",

    # Google SecOps / Chronicle SIEM - for YARA-L detection rules
    "chronicle.rules.list",
    "chronicle.rules.get",
    "chronicle.detections.list",
    "chronicle.detections.get",
    "chronicle.curatedRuleSets.list",
    "chronicle.curatedRuleSets.get",
    "chronicle.alertGroupingRules.list",
    "chronicle.alertGroupingRules.get",
    "chronicle.referenceLists.list",
    "chronicle.referenceLists.get",

    # Eventarc - for event triggers
    "eventarc.triggers.list",
    "eventarc.triggers.get",

    # Cloud Functions - for function-based detections
    "cloudfunctions.functions.list",
    "cloudfunctions.functions.get",

    # Cloud Run - for containerised detections
    "run.services.list",
    "run.services.get",

    # Required for project info
    "resourcemanager.projects.get",
  ]
}

# -----------------------------------------------------------------
# Bind Custom Role to Service Account
# -----------------------------------------------------------------

resource "google_project_iam_member" "a13e_scanner_role" {
  project = var.project_id
  role    = google_project_iam_custom_role.a13e_scanner.id
  member  = "serviceAccount:${google_service_account.a13e_scanner.email}"
}

# -----------------------------------------------------------------
# Allow WIF to Impersonate Service Account
# -----------------------------------------------------------------

resource "google_service_account_iam_member" "wif_impersonation" {
  service_account_id = google_service_account.a13e_scanner.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.a13e.name}/attribute.aws_role/${var.a13e_aws_role_name}"
}

# Token creator permission for generating access tokens
resource "google_service_account_iam_member" "token_creator" {
  service_account_id = google_service_account.a13e_scanner.name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.a13e.name}/attribute.aws_role/${var.a13e_aws_role_name}"
}

# -----------------------------------------------------------------
# Outputs
# -----------------------------------------------------------------

output "workload_identity_pool_id" {
  description = "The ID of the Workload Identity Pool"
  value       = google_iam_workload_identity_pool.a13e.workload_identity_pool_id
}

output "workload_identity_pool_name" {
  description = "The full resource name of the Workload Identity Pool"
  value       = google_iam_workload_identity_pool.a13e.name
}

output "provider_id" {
  description = "The ID of the AWS provider"
  value       = google_iam_workload_identity_pool_provider.aws.workload_identity_pool_provider_id
}

output "service_account_email" {
  description = "Email of the service account for A13E to impersonate"
  value       = google_service_account.a13e_scanner.email
}

output "a13e_configuration" {
  description = "Configuration values to provide to A13E"
  value = {
    project_id            = var.project_id
    pool_id               = google_iam_workload_identity_pool.a13e.workload_identity_pool_id
    provider_id           = google_iam_workload_identity_pool_provider.aws.workload_identity_pool_provider_id
    service_account_email = google_service_account.a13e_scanner.email
    pool_location         = "global"
  }
}
