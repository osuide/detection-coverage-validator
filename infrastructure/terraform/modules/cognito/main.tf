# AWS Cognito User Pool for Detection Coverage Validator

resource "aws_cognito_user_pool" "main" {
  name = "dcv-users-${var.environment}"

  # Use email as username
  username_attributes      = ["email"]
  auto_verified_attributes = ["email"]

  # Username configuration
  username_configuration {
    case_sensitive = false
  }

  # Password policy
  password_policy {
    minimum_length                   = 12
    require_lowercase                = true
    require_numbers                  = true
    require_symbols                  = true
    require_uppercase                = true
    temporary_password_validity_days = 7
  }

  # MFA configuration - optional but can be enforced per organization
  mfa_configuration = "OPTIONAL"

  software_token_mfa_configuration {
    enabled = true
  }

  # Account recovery
  account_recovery_setting {
    recovery_mechanism {
      name     = "verified_email"
      priority = 1
    }
  }

  # Email configuration
  email_configuration {
    email_sending_account = "COGNITO_DEFAULT"
  }

  # Verification message customization
  verification_message_template {
    default_email_option = "CONFIRM_WITH_CODE"
    email_subject        = "Your DCV verification code"
    email_message        = "Your verification code is {####}"
  }

  # Schema - custom attributes
  schema {
    name                     = "organization_id"
    attribute_data_type      = "String"
    developer_only_attribute = false
    mutable                  = true
    required                 = false

    string_attribute_constraints {
      min_length = 36
      max_length = 36
    }
  }

  # User pool add-ons - Advanced Security for threat protection
  # AUDIT: Logs suspicious activity (recommended for staging)
  # ENFORCED: Blocks risky logins (recommended for production)
  user_pool_add_ons {
    advanced_security_mode = var.advanced_security_mode
  }

  # Lambda triggers (optional - for future customization)
  # lambda_config {
  #   pre_sign_up         = aws_lambda_function.pre_signup.arn
  #   post_confirmation   = aws_lambda_function.post_confirmation.arn
  # }

  tags = {
    Environment = var.environment
    Project     = "detection-coverage-validator"
  }
}

# Cognito User Pool Domain
resource "aws_cognito_user_pool_domain" "main" {
  domain       = "dcv-${var.environment}-${random_string.domain_suffix.result}"
  user_pool_id = aws_cognito_user_pool.main.id
}

resource "random_string" "domain_suffix" {
  length  = 8
  special = false
  upper   = false
}

# Web App Client (for frontend - no secret)
resource "aws_cognito_user_pool_client" "web" {
  name         = "dcv-web-client"
  user_pool_id = aws_cognito_user_pool.main.id

  # No client secret for public web apps
  generate_secret = false

  # Explicit auth flows
  explicit_auth_flows = [
    "ALLOW_REFRESH_TOKEN_AUTH",
    "ALLOW_USER_SRP_AUTH",
    "ALLOW_USER_PASSWORD_AUTH",
  ]

  # OAuth configuration
  allowed_oauth_flows                  = ["code"]
  allowed_oauth_scopes                 = ["openid", "email", "profile"]
  allowed_oauth_flows_user_pool_client = true

  # Callback URLs
  callback_urls = var.callback_urls
  logout_urls   = var.logout_urls

  # Supported identity providers
  # Note: GitHub authentication is handled by the backend, not Cognito
  supported_identity_providers = concat(
    ["COGNITO"],
    var.enable_google_idp ? ["Google"] : []
  )

  depends_on = [
    aws_cognito_identity_provider.google,
  ]

  # Token validity
  access_token_validity  = 1  # hours
  id_token_validity      = 1  # hours
  refresh_token_validity = 30 # days

  token_validity_units {
    access_token  = "hours"
    id_token      = "hours"
    refresh_token = "days"
  }

  # Prevent user existence errors
  prevent_user_existence_errors = "ENABLED"

  # Read/write attributes
  read_attributes  = ["email", "email_verified", "name", "custom:organization_id"]
  write_attributes = ["email", "name", "custom:organization_id"]
}

# Backend API Client (with secret)
resource "aws_cognito_user_pool_client" "api" {
  name         = "dcv-api-client"
  user_pool_id = aws_cognito_user_pool.main.id

  # Generate secret for backend
  generate_secret = true

  explicit_auth_flows = [
    "ALLOW_ADMIN_USER_PASSWORD_AUTH",
    "ALLOW_REFRESH_TOKEN_AUTH",
  ]

  # Token validity
  access_token_validity  = 1
  id_token_validity      = 1
  refresh_token_validity = 30

  token_validity_units {
    access_token  = "hours"
    id_token      = "hours"
    refresh_token = "days"
  }

  prevent_user_existence_errors = "ENABLED"
}

# Google Identity Provider (optional)
resource "aws_cognito_identity_provider" "google" {
  count = var.enable_google_idp ? 1 : 0

  user_pool_id  = aws_cognito_user_pool.main.id
  provider_name = "Google"
  provider_type = "Google"

  provider_details = {
    client_id        = var.google_client_id
    client_secret    = var.google_client_secret
    authorize_scopes = "openid email profile"
  }

  attribute_mapping = {
    email    = "email"
    name     = "name"
    username = "sub"
  }

  # Prevent concurrent modifications to Cognito user pool
  # Ignore provider_details drift - AWS auto-populates computed attributes
  # (authorize_url, token_url, oidc_issuer, etc.) that cause perpetual drift.
  # See: https://github.com/hashicorp/terraform-provider-aws/issues/4831
  lifecycle {
    create_before_destroy = true
    ignore_changes        = [provider_details]
  }
}

# Note: GitHub authentication is handled by the backend directly (not via Cognito)
# Microsoft SSO has been removed from the product

# Resource Server (for API scopes)
resource "aws_cognito_resource_server" "api" {
  identifier   = "https://api.detectioncoverage.io"
  name         = "DCV API"
  user_pool_id = aws_cognito_user_pool.main.id

  scope {
    scope_name        = "read:accounts"
    scope_description = "Read cloud accounts"
  }

  scope {
    scope_name        = "write:accounts"
    scope_description = "Manage cloud accounts"
  }

  scope {
    scope_name        = "read:scans"
    scope_description = "View scan results"
  }

  scope {
    scope_name        = "write:scans"
    scope_description = "Trigger scans"
  }

  scope {
    scope_name        = "read:coverage"
    scope_description = "View coverage data"
  }
}

# ============================================================================
# Cognito Identity Pool for Azure WIF
# ============================================================================
# This Identity Pool issues OIDC JWTs for Azure Workload Identity Federation.
# It is separate from the User Pool above - used only for Azure authentication.
#
# How it works:
# 1. A13E backend calls GetOpenIdTokenForDeveloperIdentity with customer ID
# 2. Cognito returns a JWT with issuer=cognito-identity.amazonaws.com
# 3. Customer's Azure federated credential validates the JWT
# 4. Azure grants access to Defender/Policy APIs

resource "aws_cognito_identity_pool" "azure_wif" {
  identity_pool_name               = "a13e-azure-wif-${var.environment}"
  allow_unauthenticated_identities = false
  allow_classic_flow               = false

  # Developer provider name - used in GetOpenIdTokenForDeveloperIdentity API
  # This becomes part of the Logins map: {"a13e-azure-wif": "cloud-account-id"}
  developer_provider_name = "a13e-azure-wif"

  tags = {
    Environment = var.environment
    Project     = "detection-coverage-validator"
    Purpose     = "Azure WIF authentication via OIDC"
  }

  # Prevent accidental deletion - customer Cognito IdentityIds are stored in DB
  # and referenced by their Azure federated credentials
  # Per CLAUDE.md: Use lifecycle settings to prevent Cognito drift issues
  lifecycle {
    prevent_destroy = true
  }
}

# IAM role for authenticated Cognito identities
# Minimal permissions - we only need the OIDC token, not AWS credentials
resource "aws_iam_role" "azure_wif_authenticated" {
  name = "a13e-${var.environment}-azure-wif-auth"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Federated = "cognito-identity.amazonaws.com"
      }
      Action = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "cognito-identity.amazonaws.com:aud" = aws_cognito_identity_pool.azure_wif.id
        }
        "ForAnyValue:StringLike" = {
          "cognito-identity.amazonaws.com:amr" = "authenticated"
        }
      }
    }]
  })

  # No inline policy needed - we don't use AWS credentials from this role
  # The Identity Pool is only used to generate OIDC tokens for Azure

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Environment = var.environment
    Project     = "detection-coverage-validator"
  }
}

# Attach the role to the Identity Pool
resource "aws_cognito_identity_pool_roles_attachment" "azure_wif" {
  identity_pool_id = aws_cognito_identity_pool.azure_wif.id

  roles = {
    "authenticated" = aws_iam_role.azure_wif_authenticated.arn
  }
}
