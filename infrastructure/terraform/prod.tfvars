# A13E Production Environment Configuration
# Deploy with: source .env.terraform.prod && terraform apply -var-file=prod.tfvars

aws_region  = "eu-west-2"
environment = "prod"
vpc_cidr    = "10.1.0.0/16" # Different from staging (10.0.0.0/16) to enable VPC peering

# =============================================================================
# Instance Sizing (Production)
# =============================================================================
db_instance_class = "db.t3.small"    # 2 vCPU, 2GB RAM - scale up as needed
redis_node_type   = "cache.t3.small" # 2 vCPU, 1.37GB RAM

# =============================================================================
# Domain Configuration
# =============================================================================
# Production uses app.a13e.com (subdomain="" means no prefix)
domain_name  = "a13e.com"
subdomain    = "" # Empty for production: app.a13e.com, api.a13e.com
enable_https = true

# =============================================================================
# NAT Gateway (Secure by Design)
# =============================================================================
# Multi-AZ NAT Gateway for high availability
# ECS tasks run in private subnets with no public IPs
enable_nat_gateway = true
single_nat_gateway = false # Multi-AZ: 1 NAT per AZ for HA

# =============================================================================
# RDS High Availability
# =============================================================================
# Multi-AZ provides automatic failover to standby replica
enable_multi_az_rds = true

# =============================================================================
# Stripe Configuration (LIVE MODE)
# =============================================================================
# Set API keys via environment variables:
#   TF_VAR_stripe_secret_key=sk_live_...
#   TF_VAR_stripe_webhook_secret=whsec_...
#
# Production price IDs (live mode)
# Simple pricing: Individual £29/mo, Pro £250/mo
stripe_price_ids = {
  subscriber         = "price_1SfnCFAB6j5KiVeU3vDWa7BR" # Individual £29/mo
  enterprise         = "price_1SfnXvAB6j5KiVeUTqutTZu9" # Pro £250/mo
  additional_account = ""                               # Not used - simple pricing model
}

# =============================================================================
# OAuth / SSO Configuration
# =============================================================================
enable_cognito = true
cookie_domain  = ".a13e.com"

# OAuth credentials - set via environment variables:
#   TF_VAR_google_client_id=...
#   TF_VAR_google_client_secret=...
#   TF_VAR_github_client_id=...
#   TF_VAR_github_client_secret=...

# =============================================================================
# Security
# =============================================================================
# WAF IP restriction disabled - public access
waf_allowed_ips = []

# =============================================================================
# Monitoring
# =============================================================================
# More frequent GuardDuty publishing for production
guardduty_finding_publishing_frequency = "FIFTEEN_MINUTES"

# =============================================================================
# Features
# =============================================================================
# CodeBuild integration tests - staging only
enable_codebuild_tests = false

# API documentation site at docs.a13e.com
enable_docs = true

# CloudTrail audit logging (CWE-778 - security compliance)
enable_cloudtrail = true

# Compliance data - set to true only for initial data load
force_reload_compliance = false

# =============================================================================
# Support System (Google Workspace Integration)
# =============================================================================
# API key for Google Apps Script - set via environment variable:
#   TF_VAR_support_api_key=...
#
# Generate with: python -c "import secrets; print(secrets.token_urlsafe(32))"

# =============================================================================
# Google Workspace WIF Integration (Optional)
# =============================================================================
# Enable after initial production deployment
# Uses Workload Identity Federation - no service account keys required
enable_workspace_wif            = false
workspace_gcp_project_id        = ""
workspace_gcp_project_number    = ""
workspace_admin_email           = "austin@a13e.com"
workspace_service_account_email = ""
support_crm_spreadsheet_id      = ""
