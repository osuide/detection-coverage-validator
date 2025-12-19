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

# GitHub OAuth
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

# Microsoft/Azure AD OAuth
variable "microsoft_client_id" {
  description = "Microsoft/Azure AD OAuth Client ID"
  type        = string
  sensitive   = true
  default     = ""
}

variable "microsoft_client_secret" {
  description = "Microsoft/Azure AD OAuth Client Secret"
  type        = string
  sensitive   = true
  default     = ""
}

variable "microsoft_tenant_id" {
  description = "Microsoft/Azure AD Tenant ID (use 'common' for multi-tenant apps)"
  type        = string
  default     = "common"
}

# ============================================================================
# Email (SES) Configuration
# ============================================================================

variable "enable_ses" {
  description = "Enable AWS SES for email sending (password reset, team invites)"
  type        = bool
  default     = false
}
