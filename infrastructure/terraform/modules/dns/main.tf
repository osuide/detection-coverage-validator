# DNS and SSL Certificate Module
# Manages Route 53 records and ACM certificates

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
  type        = string
  description = "Root domain (e.g., a13e.com)"
}

variable "subdomain" {
  type        = string
  description = "Subdomain prefix (e.g., staging)"
  default     = ""
}

variable "alb_dns_name" {
  type        = string
  description = "ALB DNS name for API"
  default     = ""
}

variable "alb_zone_id" {
  type        = string
  description = "ALB hosted zone ID"
  default     = ""
}

variable "cloudfront_domain_name" {
  type        = string
  description = "CloudFront distribution domain name"
  default     = ""
}

variable "cloudfront_zone_id" {
  type        = string
  description = "CloudFront hosted zone ID"
  default     = "Z2FDTNDATAQYW2" # CloudFront's static zone ID
}

data "aws_route53_zone" "main" {
  name         = "${var.domain_name}."
  private_zone = false
}

locals {
  frontend_domain = var.subdomain != "" ? "${var.subdomain}.${var.domain_name}" : var.domain_name
  api_domain      = var.subdomain != "" ? "api.${var.subdomain}.${var.domain_name}" : "api.${var.domain_name}"
}

# ACM Certificate for CloudFront (must be in us-east-1)
resource "aws_acm_certificate" "cloudfront" {
  provider          = aws.us_east_1
  domain_name       = local.frontend_domain
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Name        = "a13e-${var.environment}-cloudfront-cert"
    Environment = var.environment
  }
}

# ACM Certificate for ALB (in the same region as ALB)
resource "aws_acm_certificate" "alb" {
  domain_name       = local.api_domain
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Name        = "a13e-${var.environment}-alb-cert"
    Environment = var.environment
  }
}

# DNS Validation Records for CloudFront cert
resource "aws_route53_record" "cloudfront_cert_validation" {
  for_each = {
    for dvo in aws_acm_certificate.cloudfront.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = data.aws_route53_zone.main.zone_id
}

# DNS Validation Records for ALB cert
resource "aws_route53_record" "alb_cert_validation" {
  for_each = {
    for dvo in aws_acm_certificate.alb.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = data.aws_route53_zone.main.zone_id
}

# Certificate Validation
resource "aws_acm_certificate_validation" "cloudfront" {
  provider                = aws.us_east_1
  certificate_arn         = aws_acm_certificate.cloudfront.arn
  validation_record_fqdns = [for record in aws_route53_record.cloudfront_cert_validation : record.fqdn]
}

resource "aws_acm_certificate_validation" "alb" {
  certificate_arn         = aws_acm_certificate.alb.arn
  validation_record_fqdns = [for record in aws_route53_record.alb_cert_validation : record.fqdn]
}

# Route 53 Record for Frontend (CloudFront)
# Note: These records are created unconditionally since we require domain_name to be set
# for this module to be invoked
resource "aws_route53_record" "frontend" {
  zone_id = data.aws_route53_zone.main.zone_id
  name    = local.frontend_domain
  type    = "A"

  alias {
    name                   = var.cloudfront_domain_name
    zone_id                = var.cloudfront_zone_id
    evaluate_target_health = false
  }

  depends_on = [aws_acm_certificate_validation.cloudfront]
}

# Route 53 Record for API (ALB)
resource "aws_route53_record" "api" {
  zone_id = data.aws_route53_zone.main.zone_id
  name    = local.api_domain
  type    = "A"

  alias {
    name                   = var.alb_dns_name
    zone_id                = var.alb_zone_id
    evaluate_target_health = true
  }

  depends_on = [aws_acm_certificate_validation.alb]
}

output "frontend_domain" {
  value = local.frontend_domain
}

output "api_domain" {
  value = local.api_domain
}

output "cloudfront_certificate_arn" {
  value = aws_acm_certificate_validation.cloudfront.certificate_arn
}

output "alb_certificate_arn" {
  value = aws_acm_certificate_validation.alb.certificate_arn
}

output "hosted_zone_id" {
  value = data.aws_route53_zone.main.zone_id
}
