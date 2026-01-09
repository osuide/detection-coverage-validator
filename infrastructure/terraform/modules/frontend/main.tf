# Frontend Module - S3 + CloudFront
# Serves the React frontend with optional custom domain

terraform {
  required_providers {
    aws = {
      source                = "hashicorp/aws"
      configuration_aliases = [aws, aws.us_east_1]
    }
  }
}

variable "environment" {
  type = string
}

variable "domain_name" {
  type    = string
  default = ""
}

variable "certificate_arn" {
  type    = string
  default = ""
}

variable "api_endpoint" {
  type        = string
  description = "Backend API endpoint URL"
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

# S3 Bucket for static assets
resource "aws_s3_bucket" "frontend" {
  bucket = "a13e-${var.environment}-frontend-${random_id.bucket_suffix.hex}"

  tags = {
    Name = "a13e-${var.environment}-frontend"
  }
}

resource "aws_s3_bucket_public_access_block" "frontend" {
  bucket = aws_s3_bucket.frontend.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "frontend" {
  bucket = aws_s3_bucket.frontend.id
  versioning_configuration {
    status = "Enabled"
  }
}

# Lifecycle policy to clean up old versions and reduce storage costs
# Security: Ensures old versions don't accumulate indefinitely
resource "aws_s3_bucket_lifecycle_configuration" "frontend" {
  bucket = aws_s3_bucket.frontend.id

  rule {
    id     = "expire-old-versions"
    status = "Enabled"

    # Delete non-current versions after 30 days
    noncurrent_version_expiration {
      noncurrent_days = 30
    }

    # Clean up incomplete multipart uploads after 7 days
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  rule {
    id     = "expire-delete-markers"
    status = "Enabled"

    # Clean up expired delete markers (orphaned markers with no versions)
    expiration {
      expired_object_delete_marker = true
    }

    # Only apply to objects (not folders)
    filter {
      prefix = ""
    }
  }
}

# Server-side encryption for frontend bucket
resource "aws_s3_bucket_server_side_encryption_configuration" "frontend" {
  bucket = aws_s3_bucket.frontend.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# CloudFront Origin Access Control (modern replacement for OAI)
resource "aws_cloudfront_origin_access_control" "frontend" {
  name                              = "a13e-${var.environment}-frontend-oac"
  description                       = "OAC for a13e ${var.environment} frontend"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

# S3 Bucket Policy for CloudFront OAC
resource "aws_s3_bucket_policy" "frontend" {
  bucket = aws_s3_bucket.frontend.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "AllowCloudFrontServicePrincipal"
      Effect = "Allow"
      Principal = {
        Service = "cloudfront.amazonaws.com"
      }
      Action   = "s3:GetObject"
      Resource = "${aws_s3_bucket.frontend.arn}/*"
      Condition = {
        StringEquals = {
          "AWS:SourceArn" = aws_cloudfront_distribution.frontend.arn
        }
      }
    }]
  })
}

# CloudFront Distribution
resource "aws_cloudfront_distribution" "frontend" {
  enabled             = true
  is_ipv6_enabled     = true
  default_root_object = "index.html"
  price_class         = "PriceClass_100"
  aliases             = var.domain_name != "" ? [var.domain_name] : []
  comment             = "a13e ${var.environment} frontend"
  web_acl_id          = var.waf_acl_arn != "" ? var.waf_acl_arn : null

  origin {
    domain_name              = aws_s3_bucket.frontend.bucket_regional_domain_name
    origin_id                = "S3-${aws_s3_bucket.frontend.id}"
    origin_access_control_id = aws_cloudfront_origin_access_control.frontend.id
  }

  default_cache_behavior {
    allowed_methods        = ["GET", "HEAD", "OPTIONS"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "S3-${aws_s3_bucket.frontend.id}"
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

    # Lambda@Edge for security headers (origin-response)
    dynamic "lambda_function_association" {
      for_each = var.lambda_edge_arn != "" ? [1] : []
      content {
        event_type   = "origin-response"
        lambda_arn   = var.lambda_edge_arn
        include_body = false
      }
    }
  }

  # SPA routing - return index.html for 404s
  custom_error_response {
    error_code         = 404
    response_code      = 200
    response_page_path = "/index.html"
  }

  custom_error_response {
    error_code         = 403
    response_code      = 200
    response_page_path = "/index.html"
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
    Name = "a13e-${var.environment}-frontend"
  }
}

output "cloudfront_url" {
  value = "https://${aws_cloudfront_distribution.frontend.domain_name}"
}

output "cloudfront_domain_name" {
  value = aws_cloudfront_distribution.frontend.domain_name
}

output "cloudfront_distribution_id" {
  value = aws_cloudfront_distribution.frontend.id
}

output "s3_bucket_name" {
  value = aws_s3_bucket.frontend.bucket
}

output "s3_bucket_arn" {
  value = aws_s3_bucket.frontend.arn
}
