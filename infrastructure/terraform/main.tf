terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Backend configuration - uncomment for remote state
  # backend "s3" {
  #   bucket         = "dcv-terraform-state"
  #   key            = "prod/terraform.tfstate"
  #   region         = "us-east-1"
  #   encrypt        = true
  #   dynamodb_table = "dcv-terraform-lock"
  # }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "detection-coverage-validator"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}

# Data sources
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# VPC
module "vpc" {
  source = "./modules/vpc"

  environment = var.environment
  vpc_cidr    = var.vpc_cidr
}

# Database (RDS PostgreSQL)
module "database" {
  source = "./modules/database"

  environment        = var.environment
  vpc_id            = module.vpc.vpc_id
  private_subnet_ids = module.vpc.private_subnet_ids
  db_instance_class  = var.db_instance_class
  db_name           = "dcv"
}

# Redis (ElastiCache)
module "cache" {
  source = "./modules/cache"

  environment        = var.environment
  vpc_id            = module.vpc.vpc_id
  private_subnet_ids = module.vpc.private_subnet_ids
  node_type         = var.redis_node_type
}

# API Lambda + API Gateway
module "api" {
  source = "./modules/api"

  environment        = var.environment
  vpc_id            = module.vpc.vpc_id
  private_subnet_ids = module.vpc.private_subnet_ids
  database_url      = module.database.connection_string
  redis_url         = module.cache.connection_string
}

# Scanner (Fargate)
module "scanner" {
  source = "./modules/scanner"

  environment        = var.environment
  vpc_id            = module.vpc.vpc_id
  private_subnet_ids = module.vpc.private_subnet_ids
  database_url      = module.database.connection_string
  redis_url         = module.cache.connection_string
  ecr_repository_url = module.ecr.repository_url
}

# ECR Repository
module "ecr" {
  source = "./modules/ecr"

  environment = var.environment
}

# Frontend (S3 + CloudFront)
module "frontend" {
  source = "./modules/frontend"

  environment = var.environment
  domain_name = var.domain_name
}
