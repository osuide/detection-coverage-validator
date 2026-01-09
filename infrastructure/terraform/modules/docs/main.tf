# Docs Module - S3 + CloudFront
# Serves the API documentation static site at docs.a13e.com

terraform {
  required_providers {
    aws = {
      source                = "hashicorp/aws"
      configuration_aliases = [aws, aws.us_east_1]
    }
  }
}

variable "environment" {
  type        = string
  description = "Environment name (staging, prod)"
}

variable "domain_name" {
  type        = string
  description = "Full domain for docs (e.g., docs.staging.a13e.com)"
  default     = ""
}

variable "certificate_arn" {
  type        = string
  description = "ACM certificate ARN (must be in us-east-1 for CloudFront)"
  default     = ""
}

variable "lambda_edge_arn" {
  type        = string
  description = "Lambda@Edge function ARN for security headers"
  default     = ""
}

variable "waf_acl_arn" {
  type        = string
  description = "WAF Web ACL ARN for CloudFront"
  default     = ""
}

variable "disable_caching" {
  type        = bool
  description = "Disable CloudFront caching (required when using IP-based WAF restrictions)"
  default     = false
}

resource "random_id" "bucket_suffix" {
  byte_length = 4
}

# S3 Bucket for documentation static files
resource "aws_s3_bucket" "docs" {
  bucket = "a13e-${var.environment}-docs-${random_id.bucket_suffix.hex}"

  tags = {
    Name        = "a13e-${var.environment}-docs"
    Environment = var.environment
    Purpose     = "API Documentation"
  }
}

# Block all public access - CloudFront uses OAC
resource "aws_s3_bucket_public_access_block" "docs" {
  bucket = aws_s3_bucket.docs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Enable versioning for rollback capability
resource "aws_s3_bucket_versioning" "docs" {
  bucket = aws_s3_bucket.docs.id
  versioning_configuration {
    status = "Enabled"
  }
}

# CloudFront Origin Access Control (secure S3 access)
resource "aws_cloudfront_origin_access_control" "docs" {
  name                              = "a13e-${var.environment}-docs-oac"
  description                       = "OAC for a13e ${var.environment} docs"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

# S3 Bucket Policy - Only allow CloudFront access
resource "aws_s3_bucket_policy" "docs" {
  bucket = aws_s3_bucket.docs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "AllowCloudFrontServicePrincipal"
      Effect = "Allow"
      Principal = {
        Service = "cloudfront.amazonaws.com"
      }
      Action   = "s3:GetObject"
      Resource = "${aws_s3_bucket.docs.arn}/*"
      Condition = {
        StringEquals = {
          "AWS:SourceArn" = aws_cloudfront_distribution.docs.arn
        }
      }
    }]
  })
}

# CloudFront Distribution for docs
resource "aws_cloudfront_distribution" "docs" {
  enabled             = true
  is_ipv6_enabled     = true
  default_root_object = "index.html"
  price_class         = "PriceClass_100"
  aliases             = var.domain_name != "" ? [var.domain_name] : []
  comment             = "a13e ${var.environment} API documentation"
  web_acl_id          = var.waf_acl_arn != "" ? var.waf_acl_arn : null

  origin {
    domain_name              = aws_s3_bucket.docs.bucket_regional_domain_name
    origin_id                = "S3-${aws_s3_bucket.docs.id}"
    origin_access_control_id = aws_cloudfront_origin_access_control.docs.id
  }

  default_cache_behavior {
    allowed_methods        = ["GET", "HEAD", "OPTIONS"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "S3-${aws_s3_bucket.docs.id}"
    viewer_protocol_policy = "redirect-to-https"
    compress               = true

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }

    # TTLs: disabled for staging (IP-based WAF), enabled for production (public)
    # When using IP-based WAF restrictions, caching MUST be disabled or WAF is bypassed
    min_ttl     = 0
    default_ttl = var.disable_caching ? 0 : 3600
    max_ttl     = var.disable_caching ? 0 : 86400

    # Lambda@Edge for security headers
    dynamic "lambda_function_association" {
      for_each = var.lambda_edge_arn != "" ? [1] : []
      content {
        event_type   = "origin-response"
        lambda_arn   = var.lambda_edge_arn
        include_body = false
      }
    }
  }

  # Custom error pages for static docs
  # Return 404 page for missing files (not SPA behaviour)
  custom_error_response {
    error_code            = 404
    response_code         = 404
    response_page_path    = "/404.html"
    error_caching_min_ttl = 60
  }

  custom_error_response {
    error_code            = 403
    response_code         = 404
    response_page_path    = "/404.html"
    error_caching_min_ttl = 60
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = var.certificate_arn == ""
    acm_certificate_arn            = var.certificate_arn != "" ? var.certificate_arn : null
    ssl_support_method             = var.certificate_arn != "" ? "sni-only" : null
    minimum_protocol_version       = var.certificate_arn != "" ? "TLSv1.2_2021" : null
  }

  tags = {
    Name        = "a13e-${var.environment}-docs"
    Environment = var.environment
    Purpose     = "API Documentation"
  }
}

# Outputs
output "cloudfront_url" {
  value       = "https://${aws_cloudfront_distribution.docs.domain_name}"
  description = "CloudFront distribution URL"
}

output "cloudfront_domain_name" {
  value       = aws_cloudfront_distribution.docs.domain_name
  description = "CloudFront domain name for DNS alias"
}

output "cloudfront_distribution_id" {
  value       = aws_cloudfront_distribution.docs.id
  description = "CloudFront distribution ID for cache invalidation"
}

output "cloudfront_zone_id" {
  value       = aws_cloudfront_distribution.docs.hosted_zone_id
  description = "CloudFront hosted zone ID for Route 53 alias"
}

output "s3_bucket_name" {
  value       = aws_s3_bucket.docs.bucket
  description = "S3 bucket name for deployment"
}

output "s3_bucket_arn" {
  value       = aws_s3_bucket.docs.arn
  description = "S3 bucket ARN"
}
