terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
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

locals {
  jwt_secret_key = var.jwt_secret_key != "" ? var.jwt_secret_key : random_password.jwt_secret[0].result
  # Fernet requires URL-safe base64-encoded 32-byte key
  credential_encryption_key = var.credential_encryption_key != "" ? var.credential_encryption_key : base64encode(random_password.credential_encryption[0].result)
}

# VPC
module "vpc" {
  source = "./modules/vpc"

  environment = var.environment
  vpc_cidr    = var.vpc_cidr
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
}

# Redis (ElastiCache)
module "cache" {
  source = "./modules/cache"

  environment        = var.environment
  vpc_id             = module.vpc.vpc_id
  private_subnet_ids = module.vpc.private_subnet_ids
  node_type          = var.redis_node_type
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
  alb_dns_name           = module.backend.alb_dns_name
  alb_zone_id            = module.backend.alb_zone_id
  cloudfront_domain_name = module.frontend.cloudfront_domain_name

  # Docs site (docs.a13e.com)
  enable_docs                 = var.enable_docs
  docs_cloudfront_domain_name = var.enable_docs ? module.docs[0].cloudfront_domain_name : ""
  docs_cloudfront_zone_id     = var.enable_docs ? module.docs[0].cloudfront_zone_id : "Z2FDTNDATAQYW2"
}

# Security (Lambda@Edge CSP + WAF)
module "security" {
  count  = var.enable_https && var.domain_name != "" ? 1 : 0
  source = "./modules/security"

  providers = {
    aws.us_east_1 = aws.us_east_1
  }

  environment     = var.environment
  api_domain      = var.subdomain != "" ? "api.${var.subdomain}.${var.domain_name}" : "api.${var.domain_name}"
  frontend_domain = var.subdomain != "" ? "${var.subdomain}.${var.domain_name}" : var.domain_name
  allowed_ips     = var.waf_allowed_ips
}

# Backend (ECS Fargate + ALB)
module "backend" {
  source = "./modules/backend"

  environment                = var.environment
  vpc_id                     = module.vpc.vpc_id
  public_subnet_ids          = module.vpc.public_subnet_ids
  private_subnet_ids         = module.vpc.private_subnet_ids
  database_url               = module.database.connection_string
  redis_url                  = module.cache.connection_string
  database_security_group_id = module.database.security_group_id
  redis_security_group_id    = module.cache.security_group_id
  ecr_repository_url         = module.ecr.repository_url
  domain_name                = var.domain_name != "" ? (var.subdomain != "" ? "api.${var.subdomain}.${var.domain_name}" : "api.${var.domain_name}") : ""
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
  frontend_url         = var.domain_name != "" ? (var.subdomain != "" ? "https://${var.subdomain}.${var.domain_name}" : "https://${var.domain_name}") : "http://localhost:3001"

  # Google OAuth (via Cognito)
  google_client_id = var.google_client_id

  # GitHub OAuth (handled by backend directly, not Cognito)
  github_client_id     = var.github_client_id
  github_client_secret = var.github_client_secret

  # WAF IP restriction - NOT applied to API (only frontend)
  # API relies on authentication, not IP allowlisting
  allowed_ips = []

  # Force reload compliance data (one-time migration flag)
  force_reload_compliance = var.force_reload_compliance

  # Cookie domain for cross-subdomain auth
  cookie_domain = var.cookie_domain
}

# Frontend (S3 + CloudFront)
module "frontend" {
  source = "./modules/frontend"

  providers = {
    aws           = aws
    aws.us_east_1 = aws.us_east_1
  }

  environment     = var.environment
  domain_name     = var.enable_https && var.domain_name != "" ? (var.subdomain != "" ? "${var.subdomain}.${var.domain_name}" : var.domain_name) : ""
  certificate_arn = var.enable_https && var.domain_name != "" ? module.dns[0].cloudfront_certificate_arn : ""
  api_endpoint    = module.backend.api_endpoint
  lambda_edge_arn = var.enable_https && var.domain_name != "" ? module.security[0].lambda_edge_arn : ""
  waf_acl_arn     = var.enable_https && var.domain_name != "" ? module.security[0].waf_acl_arn : ""
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
  domain_name     = var.enable_https && var.domain_name != "" ? (var.subdomain != "" ? "docs.${var.subdomain}.${var.domain_name}" : "docs.${var.domain_name}") : ""
  certificate_arn = var.enable_https && var.domain_name != "" ? module.dns[0].docs_certificate_arn : ""
  lambda_edge_arn = var.enable_https && var.domain_name != "" ? module.security[0].lambda_edge_arn : ""
  waf_acl_arn     = var.enable_https && var.domain_name != "" ? module.security[0].waf_acl_arn : ""
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
