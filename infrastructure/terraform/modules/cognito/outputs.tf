output "user_pool_id" {
  description = "Cognito User Pool ID"
  value       = aws_cognito_user_pool.main.id
}

output "user_pool_arn" {
  description = "Cognito User Pool ARN"
  value       = aws_cognito_user_pool.main.arn
}

output "user_pool_endpoint" {
  description = "Cognito User Pool endpoint"
  value       = aws_cognito_user_pool.main.endpoint
}

output "user_pool_domain" {
  description = "Cognito User Pool domain"
  value       = aws_cognito_user_pool_domain.main.domain
}

output "web_client_id" {
  description = "Web app client ID (no secret)"
  value       = aws_cognito_user_pool_client.web.id
}

output "api_client_id" {
  description = "API client ID (with secret)"
  value       = aws_cognito_user_pool_client.api.id
}

output "api_client_secret" {
  description = "API client secret"
  value       = aws_cognito_user_pool_client.api.client_secret
  sensitive   = true
}

output "cognito_domain_url" {
  description = "Full Cognito hosted UI domain URL"
  value       = "https://${aws_cognito_user_pool_domain.main.domain}.auth.${data.aws_region.current.name}.amazoncognito.com"
}

data "aws_region" "current" {}
