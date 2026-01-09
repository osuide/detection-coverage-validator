terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.27"
    }
    google = {
      source  = "hashicorp/google"
      version = "~> 7.14"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }

  # Backend configuration for remote state
  backend "s3" {
    bucket         = "a13e-terraform-state"
    key            = "staging/terraform.tfstate"
    region         = "eu-west-2"
    encrypt        = true
    dynamodb_table = "a13e-terraform-lock"
  }
}

# Default provider (eu-west-2)
provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "a13e"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}

# Provider for ACM certificates (must be us-east-1 for CloudFront)
provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"

  default_tags {
    tags = {
      Project     = "a13e"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}

# Data sources
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# =============================================================================
# Computed Domain Names
# These ensure consistent domain naming across all modules
# =============================================================================
locals {
  # Frontend domain follows main subdomain
  frontend_domain = var.subdomain != "" ? "${var.subdomain}.${var.domain_name}" : var.domain_name

  # API subdomain: if api_subdomain is null, follow main subdomain; otherwise use specified value
  _api_prefix = var.api_subdomain != null ? var.api_subdomain : var.subdomain
  api_domain  = local._api_prefix != "" ? "api.${local._api_prefix}.${var.domain_name}" : "api.${var.domain_name}"

  # Docs subdomain: same pattern as API
  _docs_prefix = var.docs_subdomain != null ? var.docs_subdomain : var.subdomain
  docs_domain  = local._docs_prefix != "" ? "docs.${local._docs_prefix}.${var.domain_name}" : "docs.${var.domain_name}"

  # Full URLs
  frontend_url = var.domain_name != "" ? "https://${local.frontend_domain}" : "http://localhost:3001"
  api_url      = var.domain_name != "" ? "https://${local.api_domain}" : "http://localhost:8000"
}

# =============================================================================
# OAuth Configuration Checks
# These ensure SSO credentials are set before applying to staging/prod
# =============================================================================

check "google_oauth_configured" {
  assert {
    condition     = var.google_client_id != "" && var.google_client_secret != ""
    error_message = <<-EOT
      ⚠️  WARNING: Google OAuth credentials not set!

      Google SSO will be DISABLED. To fix:
        export TF_VAR_google_client_id="your-client-id"
        export TF_VAR_google_client_secret="your-client-secret"

      Or source the .env.terraform file if available.
    EOT
  }
}

check "github_oauth_configured" {
  assert {
    condition     = var.github_client_id != "" && var.github_client_secret != ""
    error_message = <<-EOT
      ⚠️  WARNING: GitHub OAuth credentials not set!

      GitHub SSO will be DISABLED. To fix:
        export TF_VAR_github_client_id="your-client-id"
        export TF_VAR_github_client_secret="your-client-secret"

      Or source the .env.terraform file if available.
    EOT
  }
}

check "support_api_key_configured" {
  assert {
    condition     = var.support_api_key != ""
    error_message = <<-EOT
      ⚠️  WARNING: Support API key not set!

      The support system (Google Apps Script) will NOT work. To fix:
        export TF_VAR_support_api_key="your-support-api-key"

      Or source the .env.terraform file if available.
      The existing secret in AWS will be preserved but the task definition
      will not include the SUPPORT_API_KEY environment variable.
    EOT
  }
}

# =============================================================================

# Random JWT secret key if not provided
resource "random_password" "jwt_secret" {
  count   = var.jwt_secret_key == "" ? 1 : 0
  length  = 64
  special = true
}

# Random credential encryption key if not provided (Fernet-compatible base64)
resource "random_password" "credential_encryption" {
  count   = var.credential_encryption_key == "" ? 1 : 0
  length  = 32
  special = false
}

# Redis AUTH token - always generate (no user override needed)
# Security: Prevents unauthorized cache access even with VPC access
# ElastiCache requires 16-128 chars, printable ASCII except @, ", /
# Using alphanumeric only to avoid URL encoding issues in connection string
resource "random_password" "redis_auth" {
  length  = 64
  special = false # Alphanumeric only - avoids special char issues with ElastiCache/URLs

  # Keeper forces recreation when changed - increment version to regenerate token
  keepers = {
    version = "2" # v1 had invalid special chars, v2 is alphanumeric only
  }
}

locals {
  jwt_secret_key = var.jwt_secret_key != "" ? var.jwt_secret_key : random_password.jwt_secret[0].result
  # Fernet requires URL-safe base64-encoded 32-byte key
  credential_encryption_key = var.credential_encryption_key != "" ? var.credential_encryption_key : base64encode(random_password.credential_encryption[0].result)
}

# VPC
module "vpc" {
  source = "./modules/vpc"

  environment        = var.environment
  vpc_cidr           = var.vpc_cidr
  enable_nat_gateway = var.enable_nat_gateway
  single_nat_gateway = var.single_nat_gateway
}

# ECR Repository (for backend Docker images)
module "ecr" {
  source = "./modules/ecr"

  environment = var.environment
}

# Database (RDS PostgreSQL)
module "database" {
  source = "./modules/database"

  environment        = var.environment
  vpc_id             = module.vpc.vpc_id
  private_subnet_ids = module.vpc.private_subnet_ids
  db_instance_class  = var.db_instance_class
  db_name            = "dcv"
  multi_az           = var.enable_multi_az_rds
}

# Redis (ElastiCache)
module "cache" {
  source = "./modules/cache"

  environment        = var.environment
  vpc_id             = module.vpc.vpc_id
  private_subnet_ids = module.vpc.private_subnet_ids
  node_type          = var.redis_node_type
  auth_token         = random_password.redis_auth.result
}

# DNS and SSL Certificates (only when enable_https is true)
# Deploy in two phases:
# 1. First deploy with enable_https = false
# 2. Then set enable_https = true to create certificates and DNS records
module "dns" {
  count  = var.enable_https && var.domain_name != "" ? 1 : 0
  source = "./modules/dns"

  providers = {
    aws           = aws
    aws.us_east_1 = aws.us_east_1
  }

  environment            = var.environment
  domain_name            = var.domain_name
  subdomain              = var.subdomain
  api_subdomain          = var.api_subdomain
  docs_subdomain         = var.docs_subdomain
  alb_dns_name           = module.backend.alb_dns_name
  alb_zone_id            = module.backend.alb_zone_id
  cloudfront_domain_name = module.frontend.cloudfront_domain_name

  # Docs site (docs.a13e.com)
  enable_docs                 = var.enable_docs
  docs_cloudfront_domain_name = var.enable_docs ? module.docs[0].cloudfront_domain_name : ""
  docs_cloudfront_zone_id     = var.enable_docs ? module.docs[0].cloudfront_zone_id : "Z2FDTNDATAQYW2"

  # Marketing site (a13e.com - root domain)
  enable_marketing                 = var.enable_marketing
  marketing_cloudfront_domain_name = var.enable_marketing ? module.marketing[0].cloudfront_domain_name : ""
  marketing_cloudfront_zone_id     = var.enable_marketing ? module.marketing[0].cloudfront_zone_id : "Z2FDTNDATAQYW2"
}

# Security (Lambda@Edge CSP + WAF)
module "security" {
  count  = var.enable_https && var.domain_name != "" ? 1 : 0
  source = "./modules/security"

  providers = {
    aws.us_east_1 = aws.us_east_1
  }

  environment     = var.environment
  api_domain      = local.api_domain
  frontend_domain = local.frontend_domain
  allowed_ips     = var.waf_allowed_ips
}

# Backend (ECS Fargate + ALB)
module "backend" {
  source = "./modules/backend"

  environment                = var.environment
  vpc_id                     = module.vpc.vpc_id
  public_subnet_ids          = module.vpc.public_subnet_ids
  private_subnet_ids         = module.vpc.private_subnet_ids
  use_private_subnets        = var.enable_nat_gateway # When NAT Gateway is enabled, use private subnets
  database_url               = module.database.connection_string
  redis_url                  = module.cache.connection_string
  database_security_group_id = module.database.security_group_id
  redis_security_group_id    = module.cache.security_group_id
  ecr_repository_url         = module.ecr.repository_url
  domain_name                = var.domain_name != "" ? local.api_domain : ""
  # Certificate and HTTPS are enabled in phase 2 after initial deployment
  certificate_arn           = var.enable_https && var.domain_name != "" ? module.dns[0].alb_certificate_arn : ""
  enable_https              = var.enable_https
  jwt_secret_key            = local.jwt_secret_key
  credential_encryption_key = local.credential_encryption_key
  stripe_secret_key         = var.stripe_secret_key
  stripe_webhook_secret     = var.stripe_webhook_secret
  stripe_price_ids          = var.stripe_price_ids

  # Cognito OAuth configuration
  cognito_user_pool_id = var.enable_cognito ? module.cognito[0].user_pool_id : ""
  cognito_client_id    = var.enable_cognito ? module.cognito[0].web_client_id : ""
  cognito_domain       = var.enable_cognito ? module.cognito[0].cognito_domain_url : ""
  cognito_issuer       = var.enable_cognito ? module.cognito[0].issuer : ""
  frontend_url         = local.frontend_url

  # Google OAuth (via Cognito)
  google_client_id = var.google_client_id

  # GitHub OAuth (handled by backend directly, not Cognito)
  github_client_id     = var.github_client_id
  github_client_secret = var.github_client_secret

  # Support system API key for Google Workspace integration
  support_api_key = var.support_api_key

  # WAF IP restriction for staging API
  # Staging: IP-restricted to protect /docs endpoint from public access
  # Production: Empty list allows public access (API requires authentication anyway)
  allowed_ips = var.waf_allowed_ips

  # Force reload compliance data (one-time migration flag)
  force_reload_compliance = var.force_reload_compliance

  # Cookie domain for cross-subdomain auth
  cookie_domain = var.cookie_domain

  # Google Workspace WIF configuration
  # WIF resources are managed separately in ../terraform-gcp-wif/
  # These values are passed directly from variables (WIF already exists)
  workspace_wif_enabled           = var.enable_workspace_wif
  workspace_gcp_project_number    = var.workspace_gcp_project_number
  workspace_wif_pool_id           = var.enable_workspace_wif ? "a13e-internal-${var.environment}" : ""
  workspace_wif_provider_id       = var.enable_workspace_wif ? "aws-${var.environment}" : ""
  workspace_service_account_email = var.workspace_service_account_email
  workspace_admin_email           = var.workspace_admin_email
  support_crm_spreadsheet_id      = var.support_crm_spreadsheet_id

  # SES domain for scoped email permissions (CWE-732 fix)
  ses_domain = var.domain_name
}

# Frontend (S3 + CloudFront)
module "frontend" {
  source = "./modules/frontend"

  providers = {
    aws           = aws
    aws.us_east_1 = aws.us_east_1
  }

  environment     = var.environment
  domain_name     = var.enable_https && var.domain_name != "" ? local.frontend_domain : ""
  certificate_arn = var.enable_https && var.domain_name != "" ? module.dns[0].cloudfront_certificate_arn : ""
  api_endpoint    = module.backend.api_endpoint
  lambda_edge_arn = var.enable_https && var.domain_name != "" ? module.security[0].lambda_edge_arn : ""
  waf_acl_arn     = var.enable_https && var.domain_name != "" ? module.security[0].waf_acl_arn : ""

  # CRITICAL: Disable caching when IP-based WAF restrictions are active.
  # CloudFront caching bypasses WAF for subsequent requests, allowing
  # cached responses to be served to non-whitelisted IPs.
  disable_caching = length(var.waf_allowed_ips) > 0
}

# =============================================================================
# API Documentation Site (docs.a13e.com)
# =============================================================================
# Static documentation site hosted via S3 + CloudFront.
# Enabled via enable_docs variable in tfvars.

module "docs" {
  count  = var.enable_docs ? 1 : 0
  source = "./modules/docs"

  providers = {
    aws           = aws
    aws.us_east_1 = aws.us_east_1
  }

  environment     = var.environment
  domain_name     = var.enable_https && var.domain_name != "" ? local.docs_domain : ""
  certificate_arn = var.enable_https && var.domain_name != "" ? module.dns[0].docs_certificate_arn : ""
  lambda_edge_arn = var.enable_https && var.domain_name != "" ? module.security[0].lambda_edge_arn : ""
  waf_acl_arn     = var.enable_https && var.domain_name != "" ? module.security[0].waf_acl_arn : ""

  # CRITICAL: Disable caching when IP-based WAF restrictions are active.
  # CloudFront caching bypasses WAF for subsequent requests, allowing
  # cached responses to be served to non-whitelisted IPs.
  disable_caching = length(var.waf_allowed_ips) > 0
}

# =============================================================================
# Marketing Site (a13e.com - root domain)
# =============================================================================
# Static landing page hosted via S3 + CloudFront at the root domain.
# Enabled via enable_marketing variable in tfvars.

module "marketing" {
  count  = var.enable_marketing ? 1 : 0
  source = "./modules/marketing"

  providers = {
    aws           = aws
    aws.us_east_1 = aws.us_east_1
  }

  environment     = var.environment
  domain_name     = var.domain_name
  certificate_arn = var.enable_https && var.domain_name != "" ? module.dns[0].marketing_certificate_arn : ""
  lambda_edge_arn = var.enable_https && var.domain_name != "" ? module.security[0].lambda_edge_arn : ""
  waf_acl_arn     = var.enable_https && var.domain_name != "" ? module.security[0].waf_acl_arn : ""

  # CRITICAL: Disable caching when IP-based WAF restrictions are active.
  # CloudFront caching bypasses WAF for subsequent requests, allowing
  # cached responses to be served to non-whitelisted IPs.
  disable_caching = length(var.waf_allowed_ips) > 0
}

# =============================================================================
# Scanner Module REMOVED (December 2025)
# =============================================================================
#
# The separate scanner ECS cluster was removed because:
# 1. Scans run inline on the backend ECS tasks via ScanService.execute_scan()
# 2. The scanner cluster had 0 running services (never deployed)
# 3. It required VPC endpoints (~$72/mo) that were also unused
#
# If dedicated scan workers are needed in future:
# - Consider running scan tasks on the existing backend cluster
# - Or use Lambda for short-running scans
# - Or re-add this module with NAT Gateway for internet access
#
# module "scanner" {
#   source = "./modules/scanner"
#   environment        = var.environment
#   vpc_id             = module.vpc.vpc_id
#   private_subnet_ids = module.vpc.private_subnet_ids
#   database_url       = module.database.connection_string
#   redis_url          = module.cache.connection_string
#   ecr_repository_url = module.ecr.repository_url
# }
# =============================================================================

# Cognito (OAuth/SSO)
module "cognito" {
  count  = var.enable_cognito ? 1 : 0
  source = "./modules/cognito"

  environment = var.environment

  # Callback URLs - includes both local dev and production
  callback_urls = var.domain_name != "" ? [
    "http://localhost:3001/auth/callback",
    var.subdomain != "" ? "https://${var.subdomain}.${var.domain_name}/auth/callback" : "https://${var.domain_name}/auth/callback"
  ] : ["http://localhost:3001/auth/callback"]

  logout_urls = var.domain_name != "" ? [
    "http://localhost:3001",
    var.subdomain != "" ? "https://${var.subdomain}.${var.domain_name}" : "https://${var.domain_name}"
  ] : ["http://localhost:3001"]

  # Google OAuth (only SSO provider via Cognito)
  # Note: GitHub auth is handled by backend, Microsoft SSO removed
  enable_google_idp    = var.google_client_id != ""
  google_client_id     = var.google_client_id
  google_client_secret = var.google_client_secret

  # Advanced Security: AUDIT for staging (logs only), ENFORCED for prod (blocks risky logins)
  advanced_security_mode = var.environment == "prod" ? "ENFORCED" : "AUDIT"
}

# SES Email Service
# Note: SES is configured manually via AWS CLI for now
# To enable Terraform-managed SES, run `terraform init` then set enable_ses = true
# module "ses" {
#   count  = var.enable_ses && var.domain_name != "" ? 1 : 0
#   source = "./modules/ses"
#
#   domain      = var.domain_name
#   environment = var.environment
# }

# ============================================================================
# GuardDuty - AWS Threat Detection
# ============================================================================

resource "aws_guardduty_detector" "main" {
  count                        = var.enable_guardduty ? 1 : 0
  enable                       = true
  finding_publishing_frequency = var.guardduty_finding_publishing_frequency

  # Enable all relevant data sources
  datasources {
    s3_logs {
      enable = true
    }
    kubernetes {
      audit_logs {
        enable = true
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = true
        }
      }
    }
  }

  tags = {
    Name        = "a13e-${var.environment}-guardduty"
    Environment = var.environment
  }
}

# ============================================================================
# CloudTrail - Audit Logging
# ============================================================================
# Security: CWE-778 fix - enables comprehensive audit logging for:
# - All AWS API calls (management events)
# - Secrets Manager access (data events)
# - Multi-region coverage with log file integrity validation

module "cloudtrail" {
  source = "./modules/cloudtrail"
  count  = var.enable_cloudtrail ? 1 : 0

  environment               = var.environment
  enable_data_events        = var.environment == "prod" # S3 data events only in production (cost)
  log_retention_days        = var.environment == "prod" ? 365 : 90
  cloudwatch_retention_days = var.environment == "prod" ? 180 : 30
}

# ============================================================================
# CodeBuild Integration Tests
# ============================================================================
# Runs integration tests inside VPC with access to RDS/Redis.
# Triggered manually or on schedule via GitHub Actions.
# Cost: ~$0 (within free tier of 100 build-minutes/month)

module "codebuild" {
  count  = var.enable_codebuild_tests ? 1 : 0
  source = "./modules/codebuild"

  environment                = var.environment
  vpc_id                     = module.vpc.vpc_id
  public_subnet_ids          = module.vpc.public_subnet_ids # Public subnets have internet access
  database_security_group_id = module.database.security_group_id
  redis_security_group_id    = module.cache.security_group_id
  database_url               = module.database.connection_string
  redis_url                  = module.cache.connection_string
  secret_key                 = local.jwt_secret_key
  github_repo                = var.github_repo
}

# ============================================================================
# Google Workspace Integration (WIF)
# ============================================================================
# WIF is managed separately in ../terraform-gcp-wif/ because:
# - Requires GCP credentials (not available in GitHub Actions CI)
# - Rarely changes after initial setup
# - Internal tooling only (not customer-facing)
#
# To manage WIF resources:
#   cd ../terraform-gcp-wif
#   gcloud auth application-default login
#   terraform apply -var-file="staging.tfvars"
