output "api_endpoint" {
  description = "Backend API endpoint URL"
  value       = module.backend.api_endpoint
}

output "frontend_url" {
  description = "Frontend URL"
  value       = var.domain_name != "" ? "https://${var.subdomain != "" ? "${var.subdomain}.${var.domain_name}" : var.domain_name}" : module.frontend.cloudfront_url
}

output "database_endpoint" {
  description = "RDS endpoint"
  value       = module.database.endpoint
  sensitive   = true
}

output "redis_endpoint" {
  description = "ElastiCache endpoint"
  value       = module.cache.endpoint
  sensitive   = true
}

output "ecr_repository_url" {
  description = "ECR repository URL for backend image"
  value       = module.ecr.repository_url
}

output "alb_dns_name" {
  description = "Application Load Balancer DNS name"
  value       = module.backend.alb_dns_name
}

output "cloudfront_distribution_id" {
  description = "CloudFront distribution ID for cache invalidation"
  value       = module.frontend.cloudfront_distribution_id
}

output "s3_bucket_name" {
  description = "S3 bucket name for frontend deployment"
  value       = module.frontend.s3_bucket_name
}

output "ecs_cluster_arn" {
  description = "ECS cluster ARN"
  value       = module.backend.ecs_cluster_arn
}

output "ecs_cluster_name" {
  description = "ECS cluster name"
  value       = module.backend.ecs_cluster_name
}

output "ecs_service_name" {
  description = "ECS service name for deployment"
  value       = module.backend.ecs_service_name
}

output "vpc_private_subnets" {
  description = "Private subnet IDs for ECS tasks"
  value       = module.vpc.private_subnet_ids
}

output "vpc_public_subnets" {
  description = "Public subnet IDs"
  value       = module.vpc.public_subnet_ids
}

output "ecs_security_group_id" {
  description = "ECS tasks security group ID"
  value       = module.backend.ecs_security_group_id
}

# Cognito outputs (only when enabled)
output "cognito_user_pool_id" {
  description = "Cognito User Pool ID"
  value       = var.enable_cognito ? module.cognito[0].user_pool_id : null
}

output "cognito_web_client_id" {
  description = "Cognito Web Client ID (for frontend)"
  value       = var.enable_cognito ? module.cognito[0].web_client_id : null
}

output "cognito_domain_url" {
  description = "Cognito OAuth domain URL"
  value       = var.enable_cognito ? module.cognito[0].cognito_domain_url : null
}

output "cognito_enabled_providers" {
  description = "List of enabled OAuth providers"
  value       = var.enable_cognito ? module.cognito[0].enabled_providers : []
  sensitive   = true
}

# CodeBuild outputs (only when enabled)
output "codebuild_project_name" {
  description = "CodeBuild project name for integration tests"
  value       = var.enable_codebuild_tests ? module.codebuild[0].project_name : null
}

output "codebuild_project_arn" {
  description = "CodeBuild project ARN"
  value       = var.enable_codebuild_tests ? module.codebuild[0].project_arn : null
}

output "codebuild_github_actions_policy_arn" {
  description = "IAM policy ARN to attach to GitHub Actions user for CodeBuild access"
  value       = var.enable_codebuild_tests ? module.codebuild[0].github_actions_policy_arn : null
}
