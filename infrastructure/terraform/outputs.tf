output "api_endpoint" {
  description = "API Gateway endpoint URL"
  value       = module.api.api_endpoint
}

output "frontend_url" {
  description = "CloudFront distribution URL"
  value       = module.frontend.cloudfront_url
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
  description = "ECR repository URL for scanner image"
  value       = module.ecr.repository_url
}
