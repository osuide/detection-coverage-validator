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

  # User pool add-ons
  user_pool_add_ons {
    advanced_security_mode = "AUDIT"
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
  supported_identity_providers = concat(
    ["COGNITO"],
    var.enable_google_idp ? ["Google"] : [],
    var.enable_github_idp ? ["GitHub"] : [],
    var.enable_microsoft_idp ? ["Microsoft"] : []
  )

  depends_on = [
    aws_cognito_identity_provider.google,
    aws_cognito_identity_provider.github,
    aws_cognito_identity_provider.microsoft,
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
}

# GitHub Identity Provider (optional) - Uses OIDC
resource "aws_cognito_identity_provider" "github" {
  count = var.enable_github_idp ? 1 : 0

  user_pool_id  = aws_cognito_user_pool.main.id
  provider_name = "GitHub"
  provider_type = "OIDC"

  provider_details = {
    client_id                     = var.github_client_id
    client_secret                 = var.github_client_secret
    authorize_scopes              = "openid read:user user:email"
    attributes_request_method     = "GET"
    oidc_issuer                   = "https://github.com"
    authorize_url                 = "https://github.com/login/oauth/authorize"
    token_url                     = "https://github.com/login/oauth/access_token"
    attributes_url                = "https://api.github.com/user"
    jwks_uri                      = "https://token.actions.githubusercontent.com/.well-known/jwks"
  }

  attribute_mapping = {
    email    = "email"
    name     = "name"
    username = "sub"
    picture  = "avatar_url"
  }
}

# Microsoft/Azure AD Identity Provider (optional) - Uses OIDC
resource "aws_cognito_identity_provider" "microsoft" {
  count = var.enable_microsoft_idp ? 1 : 0

  user_pool_id  = aws_cognito_user_pool.main.id
  provider_name = "Microsoft"
  provider_type = "OIDC"

  provider_details = {
    client_id                     = var.microsoft_client_id
    client_secret                 = var.microsoft_client_secret
    authorize_scopes              = "openid email profile"
    attributes_request_method     = "GET"
    oidc_issuer                   = "https://login.microsoftonline.com/${var.microsoft_tenant_id}/v2.0"
    authorize_url                 = "https://login.microsoftonline.com/${var.microsoft_tenant_id}/oauth2/v2.0/authorize"
    token_url                     = "https://login.microsoftonline.com/${var.microsoft_tenant_id}/oauth2/v2.0/token"
    attributes_url                = "https://graph.microsoft.com/oidc/userinfo"
    jwks_uri                      = "https://login.microsoftonline.com/${var.microsoft_tenant_id}/discovery/v2.0/keys"
  }

  attribute_mapping = {
    email    = "email"
    name     = "name"
    username = "sub"
  }
}

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
