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

# Microsoft/Azure AD OAuth (set via environment variables)
# microsoft_client_id     = ""  # Set via TF_VAR_microsoft_client_id
# microsoft_client_secret = ""  # Set via TF_VAR_microsoft_client_secret
microsoft_tenant_id = "common" # "common" allows any Azure AD tenant (multi-tenant)
