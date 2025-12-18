# A13E Detection Coverage Validator - GCP Terraform Module
#
# This module creates a custom IAM role and service account with the minimum
# permissions required for A13E to scan your security detection configurations.
#
# Usage:
#   module "a13e_scanner" {
#     source     = "./a13e-gcp"
#     project_id = "my-project-123"
#   }
#
# Then copy the service_account_email to your A13E dashboard.

terraform {
  required_version = ">= 1.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 4.0"
    }
  }
}

variable "project_id" {
  description = "GCP Project ID"
  type        = string
}

variable "role_id" {
  description = "ID for the custom IAM role"
  type        = string
  default     = "a13e_detection_scanner"
}

variable "service_account_id" {
  description = "ID for the service account"
  type        = string
  default     = "a13e-scanner"
}

variable "create_sa_key" {
  description = "Whether to create a service account key (less secure, use workload identity instead)"
  type        = bool
  default     = false
}

# Enable required APIs
resource "google_project_service" "required_apis" {
  for_each = toset([
    "logging.googleapis.com",
    "monitoring.googleapis.com",
    "securitycenter.googleapis.com",
    "eventarc.googleapis.com",
    "cloudfunctions.googleapis.com",
    "run.googleapis.com",
    "iam.googleapis.com",
    "cloudresourcemanager.googleapis.com",
  ])

  project = var.project_id
  service = each.value

  disable_on_destroy = false
}

# Custom IAM role with minimum permissions
resource "google_project_iam_custom_role" "a13e_scanner" {
  project     = var.project_id
  role_id     = var.role_id
  title       = "A13E Detection Scanner"
  description = "Minimum permissions for A13E to scan security detection configurations. Read-only access to logging, monitoring, and security services."

  permissions = [
    # Cloud Logging
    "logging.logMetrics.list",
    "logging.logMetrics.get",
    "logging.sinks.list",
    "logging.sinks.get",

    # Cloud Monitoring
    "monitoring.alertPolicies.list",
    "monitoring.alertPolicies.get",
    "monitoring.notificationChannels.list",
    "monitoring.notificationChannels.get",

    # Security Command Center
    "securitycenter.findings.list",
    "securitycenter.findings.get",
    "securitycenter.sources.list",
    "securitycenter.sources.get",

    # Eventarc
    "eventarc.triggers.list",
    "eventarc.triggers.get",

    # Cloud Functions
    "cloudfunctions.functions.list",
    "cloudfunctions.functions.get",

    # Cloud Run
    "run.services.list",
    "run.services.get",

    # Resource Manager
    "resourcemanager.projects.get",
  ]

  depends_on = [google_project_service.required_apis]
}

# Service account for A13E
resource "google_service_account" "a13e_scanner" {
  project      = var.project_id
  account_id   = var.service_account_id
  display_name = "A13E Detection Scanner"
  description  = "Service account for A13E Detection Coverage Validator. Read-only access to security configurations."

  depends_on = [google_project_service.required_apis]
}

# Bind custom role to service account
resource "google_project_iam_member" "a13e_scanner_role" {
  project = var.project_id
  role    = google_project_iam_custom_role.a13e_scanner.id
  member  = "serviceAccount:${google_service_account.a13e_scanner.email}"
}

# Optional: Service account key (not recommended - use workload identity)
resource "google_service_account_key" "a13e_scanner" {
  count              = var.create_sa_key ? 1 : 0
  service_account_id = google_service_account.a13e_scanner.name
}

output "service_account_email" {
  description = "Email of the A13E scanner service account - copy this to your A13E dashboard"
  value       = google_service_account.a13e_scanner.email
}

output "service_account_id" {
  description = "ID of the service account"
  value       = google_service_account.a13e_scanner.account_id
}

output "custom_role_id" {
  description = "ID of the custom IAM role"
  value       = google_project_iam_custom_role.a13e_scanner.id
}

output "project_id" {
  description = "GCP Project ID"
  value       = var.project_id
}

output "service_account_key" {
  description = "Service account key (base64 encoded JSON) - only if create_sa_key=true"
  value       = var.create_sa_key ? google_service_account_key.a13e_scanner[0].private_key : null
  sensitive   = true
}

output "permissions_granted" {
  description = "List of permissions granted to the service account"
  value = [
    "logging.logMetrics.list",
    "logging.logMetrics.get",
    "logging.sinks.list",
    "logging.sinks.get",
    "monitoring.alertPolicies.list",
    "monitoring.alertPolicies.get",
    "monitoring.notificationChannels.list",
    "monitoring.notificationChannels.get",
    "securitycenter.findings.list",
    "securitycenter.findings.get",
    "securitycenter.sources.list",
    "securitycenter.sources.get",
    "eventarc.triggers.list",
    "eventarc.triggers.get",
    "cloudfunctions.functions.list",
    "cloudfunctions.functions.get",
    "run.services.list",
    "run.services.get",
    "resourcemanager.projects.get",
  ]
}
