variable "aws_region" {
  description = "AWS region to deploy to"
  type        = string
  default     = "eu-west-2"
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "staging"
}

variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "db_instance_class" {
  description = "RDS instance class"
  type        = string
  default     = "db.t3.micro"
}

variable "redis_node_type" {
  description = "ElastiCache node type"
  type        = string
  default     = "cache.t3.micro"
}

variable "domain_name" {
  description = "Root domain name (e.g., a13e.com)"
  type        = string
  default     = ""
}

variable "subdomain" {
  description = "Subdomain prefix (e.g., staging)"
  type        = string
  default     = ""
}

variable "enable_https" {
  description = "Enable HTTPS (set to true after initial deployment when certificates are validated)"
  type        = bool
  default     = false
}

variable "jwt_secret_key" {
  description = "JWT secret key for token signing (auto-generated if not provided)"
  type        = string
  sensitive   = true
  default     = ""
}

variable "credential_encryption_key" {
  description = "Fernet key for encrypting cloud credentials (auto-generated if not provided)"
  type        = string
  sensitive   = true
  default     = ""
}

variable "stripe_secret_key" {
  description = "Stripe secret API key"
  type        = string
  sensitive   = true
  default     = ""
}

variable "stripe_webhook_secret" {
  description = "Stripe webhook signing secret"
  type        = string
  sensitive   = true
  default     = ""
}

variable "stripe_price_ids" {
  description = "Stripe price IDs for subscription plans"
  type = object({
    subscriber         = string
    enterprise         = string
    additional_account = string
  })
  default = {
    subscriber         = ""
    enterprise         = ""
    additional_account = ""
  }
}

# ============================================================================
# OAuth / SSO Configuration
# ============================================================================

variable "enable_cognito" {
  description = "Enable AWS Cognito for OAuth/SSO"
  type        = bool
  default     = false
}

# Google OAuth
variable "google_client_id" {
  description = "Google OAuth Client ID"
  type        = string
  sensitive   = true
  default     = ""
}

variable "google_client_secret" {
  description = "Google OAuth Client Secret"
  type        = string
  sensitive   = true
  default     = ""
}

# GitHub OAuth (handled by backend directly, not Cognito)
variable "github_client_id" {
  description = "GitHub OAuth App Client ID"
  type        = string
  sensitive   = true
  default     = ""
}

variable "github_client_secret" {
  description = "GitHub OAuth App Client Secret"
  type        = string
  sensitive   = true
  default     = ""
}

# Note: Microsoft SSO has been removed from the product

# ============================================================================
# Email (SES) Configuration
# ============================================================================

variable "enable_ses" {
  description = "Enable AWS SES for email sending (password reset, team invites)"
  type        = bool
  default     = false
}

# ============================================================================
# WAF IP Restriction (for limiting access during development/maintenance)
# ============================================================================

variable "waf_allowed_ips" {
  description = "List of IP addresses (CIDR notation) allowed to access the site. Empty list allows all traffic."
  type        = list(string)
  default     = []
}

# ============================================================================
# Compliance Data Migration
# ============================================================================

variable "force_reload_compliance" {
  description = "Force reload compliance framework data on backend startup. Set to true after updating JSON files, then set back to false."
  type        = bool
  default     = false
}

variable "cookie_domain" {
  description = "Cookie domain for cross-subdomain auth. Required when frontend and API are on different subdomains (e.g., '.a13e.com'). Leave empty for same-origin setups."
  type        = string
  default     = ""
}

# ============================================================================
# GuardDuty Configuration
# ============================================================================

variable "guardduty_finding_publishing_frequency" {
  description = "Frequency of GuardDuty finding exports. FIFTEEN_MINUTES for prod, SIX_HOURS for staging."
  type        = string
  default     = "SIX_HOURS"

  validation {
    condition     = contains(["FIFTEEN_MINUTES", "ONE_HOUR", "SIX_HOURS"], var.guardduty_finding_publishing_frequency)
    error_message = "guardduty_finding_publishing_frequency must be FIFTEEN_MINUTES, ONE_HOUR, or SIX_HOURS."
  }
}

# ============================================================================
# CodeBuild Integration Tests
# ============================================================================

variable "enable_codebuild_tests" {
  description = "Enable CodeBuild for running integration tests inside VPC"
  type        = bool
  default     = false
}

variable "github_repo" {
  description = "GitHub repository in format owner/repo for CodeBuild source"
  type        = string
  default     = "osuide/detection-coverage-validator"
}
