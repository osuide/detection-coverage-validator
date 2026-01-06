# A13E Staging Environment Configuration
# Deploy with: terraform apply -var-file=staging.tfvars

aws_region  = "eu-west-2"
environment = "staging"
vpc_cidr    = "10.0.0.0/16"

# Cost-optimized instance sizes for staging
db_instance_class = "db.t3.micro"
redis_node_type   = "cache.t3.micro"

# Domain configuration
domain_name  = "a13e.com"
subdomain    = "staging"
enable_https = true

# Stripe configuration (test mode)
# These will be set via environment variables or Terraform Cloud
# stripe_secret_key   = ""  # Set via TF_VAR_stripe_secret_key
# stripe_webhook_secret = ""  # Set via TF_VAR_stripe_webhook_secret

stripe_price_ids = {
  subscriber         = "price_1SfohWAB6j5KiVeUArcQIWFT"
  enterprise         = "price_1SfohZAB6j5KiVeU4LWn8SIB"
  additional_account = "price_1SfohcAB6j5KiVeUwuNNhEEW"
}

# ============================================================================
# OAuth / SSO Configuration
# ============================================================================
# Enable Cognito for OAuth (Google, GitHub, Microsoft SSO)
enable_cognito = true

# Google OAuth (set via environment variables)
# google_client_id     = ""  # Set via TF_VAR_google_client_id
# google_client_secret = ""  # Set via TF_VAR_google_client_secret

# GitHub OAuth (set via environment variables)
# github_client_id     = ""  # Set via TF_VAR_github_client_id
# github_client_secret = ""  # Set via TF_VAR_github_client_secret

# Support API key for Google Workspace integration
# support_api_key = ""  # Set via TF_VAR_support_api_key

# Note: GitHub authentication is handled by the backend directly (not via Cognito)
# Microsoft SSO has been removed from the product

# ============================================================================
# WAF IP Restriction
# ============================================================================
# Restrict staging access to specific IPs only (CIDR notation)
# Set to [] to allow all traffic (authentication handles access control)
waf_allowed_ips = []

# ============================================================================
# Compliance Data Migration
# ============================================================================
# Set to true to force reload compliance framework data on next deployment
# IMPORTANT: Set back to false after the data has been reloaded
force_reload_compliance = false

# ============================================================================
# Cookie Domain for Cross-Subdomain Auth
# ============================================================================
# Required when frontend (staging.a13e.com) and API (api.staging.a13e.com) are
# on different subdomains. The leading dot makes cookies accessible to all subdomains.
cookie_domain = ".a13e.com"

# ============================================================================
# CodeBuild Integration Tests
# ============================================================================
# Enables CodeBuild project for running integration tests inside VPC.
# Triggered manually via GitHub Actions or weekly scheduled runs.
enable_codebuild_tests = true

# ============================================================================
# API Documentation Site
# ============================================================================
# Enable docs.staging.a13e.com for public API documentation.
# Uses S3 + CloudFront with the same security controls as frontend.
enable_docs = true

# ============================================================================
# Marketing Site (Root Domain)
# ============================================================================
# Enable marketing landing page at a13e.com (root domain).
# Uses S3 + CloudFront with the same security controls as frontend.
# Note: This is shared across staging and production - only deploy once.
enable_marketing = true

# ============================================================================
# CloudTrail Audit Logging (CWE-778)
# ============================================================================
# Enables audit logging for all AWS API calls and Secrets Manager access.
# Required for security compliance and incident investigation.
enable_cloudtrail = true

# ============================================================================
# Google Workspace Integration (WIF)
# ============================================================================
# Enables automated support, CRM, and operations via Google Workspace APIs.
# Uses Workload Identity Federation - no service account keys required.
# See docs/designs/google-workspace-automation.md for setup instructions.
enable_workspace_wif            = true
workspace_gcp_project_id        = "a13e-workspace-automation"
workspace_gcp_project_number    = "323306277338"
workspace_admin_email           = "austin@a13e.com"
workspace_service_account_email = "workspace-automation@a13e-workspace-automation.iam.gserviceaccount.com"
support_crm_spreadsheet_id      = "1UMVumA3LyD5fLjd32EQYi_h3oaQiOrvkpbn3oyDZSsU"
