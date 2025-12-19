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

# Random JWT secret key if not provided
resource "random_password" "jwt_secret" {
  count   = var.jwt_secret_key == "" ? 1 : 0
  length  = 64
  special = true
}

locals {
  jwt_secret_key = var.jwt_secret_key != "" ? var.jwt_secret_key : random_password.jwt_secret[0].result
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
  certificate_arn            = var.enable_https && var.domain_name != "" ? module.dns[0].alb_certificate_arn : ""
  enable_https               = var.enable_https
  jwt_secret_key             = local.jwt_secret_key
  stripe_secret_key          = var.stripe_secret_key
  stripe_webhook_secret      = var.stripe_webhook_secret
  stripe_price_ids           = var.stripe_price_ids

  # Cognito OAuth configuration
  cognito_user_pool_id = var.enable_cognito ? module.cognito[0].user_pool_id : ""
  cognito_client_id    = var.enable_cognito ? module.cognito[0].web_client_id : ""
  cognito_domain       = var.enable_cognito ? module.cognito[0].cognito_domain_url : ""
  cognito_issuer       = var.enable_cognito ? module.cognito[0].issuer : ""
  frontend_url         = var.domain_name != "" ? (var.subdomain != "" ? "https://${var.subdomain}.${var.domain_name}" : "https://${var.domain_name}") : "http://localhost:3001"

  # OAuth provider client IDs (for backend to know which providers are enabled)
  google_client_id     = var.google_client_id
  github_client_id     = var.github_client_id
  github_client_secret = var.github_client_secret
  microsoft_client_id  = var.microsoft_client_id
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

# Scanner (Fargate - uses same cluster as backend for staging)
module "scanner" {
  source = "./modules/scanner"

  environment        = var.environment
  vpc_id             = module.vpc.vpc_id
  private_subnet_ids = module.vpc.private_subnet_ids
  database_url       = module.database.connection_string
  redis_url          = module.cache.connection_string
  ecr_repository_url = module.ecr.repository_url
}

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

  # Google OAuth
  enable_google_idp    = var.google_client_id != ""
  google_client_id     = var.google_client_id
  google_client_secret = var.google_client_secret

  # GitHub OAuth
  enable_github_idp    = var.github_client_id != ""
  github_client_id     = var.github_client_id
  github_client_secret = var.github_client_secret

  # Microsoft/Azure AD OAuth
  enable_microsoft_idp    = var.microsoft_client_id != ""
  microsoft_client_id     = var.microsoft_client_id
  microsoft_client_secret = var.microsoft_client_secret
  microsoft_tenant_id     = var.microsoft_tenant_id
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
