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
  value       = "https://${aws_cognito_user_pool_domain.main.domain}.auth.${data.aws_region.current.region}.amazoncognito.com"
}

output "enabled_providers" {
  description = "List of enabled identity providers"
  # Note: GitHub auth is handled by backend directly, Microsoft SSO removed
  value = concat(
    ["COGNITO"],
    var.enable_google_idp ? ["Google"] : []
  )
}

output "issuer" {
  description = "Cognito issuer URL for JWT verification"
  value       = "https://cognito-idp.${data.aws_region.current.region}.amazonaws.com/${aws_cognito_user_pool.main.id}"
}

output "authorization_endpoint" {
  description = "OAuth authorization endpoint"
  value       = "https://${aws_cognito_user_pool_domain.main.domain}.auth.${data.aws_region.current.region}.amazoncognito.com/oauth2/authorize"
}

output "token_endpoint" {
  description = "OAuth token endpoint"
  value       = "https://${aws_cognito_user_pool_domain.main.domain}.auth.${data.aws_region.current.region}.amazoncognito.com/oauth2/token"
}

data "aws_region" "current" {}

# Azure WIF Identity Pool outputs
output "azure_wif_identity_pool_id" {
  description = "Cognito Identity Pool ID for Azure WIF (used in COGNITO_IDENTITY_POOL_ID env var)"
  value       = aws_cognito_identity_pool.azure_wif.id
}

output "azure_wif_identity_pool_arn" {
  description = "Cognito Identity Pool ARN for Azure WIF (used in IAM policies)"
  value       = aws_cognito_identity_pool.azure_wif.arn
}
