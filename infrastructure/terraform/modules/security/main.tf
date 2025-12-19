# Security Module - Lambda@Edge CSP Headers + WAF ACL
# Lambda@Edge must be deployed in us-east-1 for CloudFront

terraform {
  required_providers {
    aws = {
      source                = "hashicorp/aws"
      configuration_aliases = [aws.us_east_1]
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
    }
  }
}

variable "environment" {
  type = string
}

variable "api_domain" {
  type        = string
  description = "API domain for CSP connect-src directive"
}

variable "frontend_domain" {
  type        = string
  description = "Frontend domain for CSP"
}

# ============================================================================
# Lambda@Edge for Security Headers
# ============================================================================

# IAM Role for Lambda@Edge
resource "aws_iam_role" "lambda_edge" {
  provider = aws.us_east_1
  name     = "a13e-${var.environment}-lambda-edge-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = [
          "lambda.amazonaws.com",
          "edgelambda.amazonaws.com"
        ]
      }
    }]
  })

  tags = {
    Name = "a13e-${var.environment}-lambda-edge-role"
  }
}

resource "aws_iam_role_policy_attachment" "lambda_edge_basic" {
  provider   = aws.us_east_1
  role       = aws_iam_role.lambda_edge.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Lambda function code
data "archive_file" "security_headers" {
  type        = "zip"
  output_path = "${path.module}/security-headers.zip"

  source {
    content  = <<-EOF
'use strict';

/**
 * A13E Lambda@Edge Security Headers Function
 * Adds comprehensive security headers to CloudFront responses
 */

exports.handler = async (event) => {
  const response = event.Records[0].cf.response;
  const headers = response.headers;

  // Build Content Security Policy
  const csp = [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline' https://js.stripe.com",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob: https:",
    "connect-src 'self' https://${var.api_domain} https://api.stripe.com",
    "frame-src https://js.stripe.com",
    "font-src 'self' data:",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "upgrade-insecure-requests"
  ].join('; ');

  // Remove revealing AWS headers
  delete headers['x-amz-server-side-encryption'];
  delete headers['x-amz-version-id'];
  delete headers['x-amz-id-2'];
  delete headers['x-amz-request-id'];
  delete headers['via'];

  // Set custom server header
  headers['server'] = [{ key: 'Server', value: 'a13e' }];

  // Security headers
  headers['content-security-policy'] = [{
    key: 'Content-Security-Policy',
    value: csp
  }];

  headers['strict-transport-security'] = [{
    key: 'Strict-Transport-Security',
    value: 'max-age=31536000; includeSubDomains; preload'
  }];

  headers['x-content-type-options'] = [{
    key: 'X-Content-Type-Options',
    value: 'nosniff'
  }];

  headers['x-frame-options'] = [{
    key: 'X-Frame-Options',
    value: 'DENY'
  }];

  headers['x-xss-protection'] = [{
    key: 'X-XSS-Protection',
    value: '1; mode=block'
  }];

  headers['referrer-policy'] = [{
    key: 'Referrer-Policy',
    value: 'strict-origin-when-cross-origin'
  }];

  headers['permissions-policy'] = [{
    key: 'Permissions-Policy',
    value: 'geolocation=(), camera=(), microphone=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()'
  }];

  headers['cross-origin-opener-policy'] = [{
    key: 'Cross-Origin-Opener-Policy',
    value: 'same-origin'
  }];

  headers['cross-origin-embedder-policy'] = [{
    key: 'Cross-Origin-Embedder-Policy',
    value: 'credentialless'
  }];

  headers['cross-origin-resource-policy'] = [{
    key: 'Cross-Origin-Resource-Policy',
    value: 'same-site'
  }];

  return response;
};
EOF
    filename = "index.js"
  }
}

# Lambda@Edge function (must be in us-east-1)
resource "aws_lambda_function" "security_headers" {
  provider         = aws.us_east_1
  filename         = data.archive_file.security_headers.output_path
  source_code_hash = data.archive_file.security_headers.output_base64sha256
  function_name    = "a13e-${var.environment}-security-headers"
  role             = aws_iam_role.lambda_edge.arn
  handler          = "index.handler"
  runtime          = "nodejs20.x"
  publish          = true
  timeout          = 5
  memory_size      = 128

  tags = {
    Name = "a13e-${var.environment}-security-headers"
  }
}

# ============================================================================
# WAF Web ACL - OWASP Top 10 Protection
# ============================================================================

resource "aws_wafv2_web_acl" "frontend" {
  provider    = aws.us_east_1
  name        = "a13e-${var.environment}-frontend-waf"
  description = "WAF ACL for A13E ${var.environment} frontend - OWASP protection"
  scope       = "CLOUDFRONT"

  default_action {
    allow {}
  }

  # Rule 1: AWS Managed Core Rule Set (CRS) - OWASP Top 10
  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 1

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "a13e-${var.environment}-crs"
      sampled_requests_enabled   = true
    }
  }

  # Rule 2: Known Bad Inputs
  rule {
    name     = "AWSManagedRulesKnownBadInputsRuleSet"
    priority = 2

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "a13e-${var.environment}-known-bad-inputs"
      sampled_requests_enabled   = true
    }
  }

  # Rule 3: SQL Injection Protection
  rule {
    name     = "AWSManagedRulesSQLiRuleSet"
    priority = 3

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesSQLiRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "a13e-${var.environment}-sqli"
      sampled_requests_enabled   = true
    }
  }

  # Rule 4: Amazon IP Reputation List (known bad actors)
  rule {
    name     = "AWSManagedRulesAmazonIpReputationList"
    priority = 4

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesAmazonIpReputationList"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "a13e-${var.environment}-ip-reputation"
      sampled_requests_enabled   = true
    }
  }

  # Rule 5: Anonymous IP List (Tor, VPNs, proxies - count only for monitoring)
  rule {
    name     = "AWSManagedRulesAnonymousIpList"
    priority = 5

    override_action {
      count {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesAnonymousIpList"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "a13e-${var.environment}-anonymous-ip"
      sampled_requests_enabled   = true
    }
  }

  # Rule 6: Rate Limiting - 2000 requests per 5 minutes per IP
  rule {
    name     = "RateLimitRule"
    priority = 6

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = 2000
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "a13e-${var.environment}-rate-limit"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "a13e-${var.environment}-waf"
    sampled_requests_enabled   = true
  }

  tags = {
    Name = "a13e-${var.environment}-frontend-waf"
  }
}

# ============================================================================
# Outputs
# ============================================================================

output "lambda_edge_arn" {
  description = "Lambda@Edge function ARN with version for CloudFront"
  value       = aws_lambda_function.security_headers.qualified_arn
}

output "waf_acl_arn" {
  description = "WAF Web ACL ARN for CloudFront"
  value       = aws_wafv2_web_acl.frontend.arn
}

output "waf_acl_id" {
  description = "WAF Web ACL ID"
  value       = aws_wafv2_web_acl.frontend.id
}
