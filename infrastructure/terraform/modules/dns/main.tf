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

variable "api_subdomain" {
  type        = string
  description = "API subdomain prefix. If null, follows main subdomain pattern. Set to empty string for api.domain.com"
  default     = null
}

variable "docs_subdomain" {
  type        = string
  description = "Docs subdomain prefix. If null, follows main subdomain pattern. Set to empty string for docs.domain.com"
  default     = null
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

# Docs site variables
variable "enable_docs" {
  type        = bool
  description = "Enable docs.a13e.com subdomain"
  default     = false
}

variable "docs_cloudfront_domain_name" {
  type        = string
  description = "CloudFront distribution domain name for docs"
  default     = ""
}

variable "docs_cloudfront_zone_id" {
  type        = string
  description = "CloudFront hosted zone ID for docs"
  default     = "Z2FDTNDATAQYW2" # CloudFront's static zone ID
}

# Marketing site variables (root domain)
variable "enable_marketing" {
  type        = bool
  description = "Enable marketing site at root domain (a13e.com)"
  default     = false
}

variable "marketing_cloudfront_domain_name" {
  type        = string
  description = "CloudFront distribution domain name for marketing site"
  default     = ""
}

variable "marketing_cloudfront_zone_id" {
  type        = string
  description = "CloudFront hosted zone ID for marketing site"
  default     = "Z2FDTNDATAQYW2" # CloudFront's static zone ID
}

data "aws_route53_zone" "main" {
  name         = "${var.domain_name}."
  private_zone = false
}

locals {
  frontend_domain = var.subdomain != "" ? "${var.subdomain}.${var.domain_name}" : var.domain_name

  # API subdomain: if api_subdomain is null, follow main subdomain pattern; otherwise use specified value
  # Examples: api_subdomain=null + subdomain="staging" → api.staging.a13e.com
  #           api_subdomain="" + subdomain="app" → api.a13e.com
  _api_prefix = var.api_subdomain != null ? var.api_subdomain : var.subdomain
  api_domain  = local._api_prefix != "" ? "api.${local._api_prefix}.${var.domain_name}" : "api.${var.domain_name}"

  # Docs subdomain: same pattern as API
  _docs_prefix = var.docs_subdomain != null ? var.docs_subdomain : var.subdomain
  docs_domain  = local._docs_prefix != "" ? "docs.${local._docs_prefix}.${var.domain_name}" : "docs.${var.domain_name}"
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

# =============================================================================
# Docs Site (docs.a13e.com)
# =============================================================================

# ACM Certificate for Docs CloudFront (must be in us-east-1)
resource "aws_acm_certificate" "docs" {
  count             = var.enable_docs ? 1 : 0
  provider          = aws.us_east_1
  domain_name       = local.docs_domain
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Name        = "a13e-${var.environment}-docs-cert"
    Environment = var.environment
  }
}

# DNS Validation Records for Docs cert
resource "aws_route53_record" "docs_cert_validation" {
  for_each = var.enable_docs ? {
    for dvo in aws_acm_certificate.docs[0].domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  } : {}

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = data.aws_route53_zone.main.zone_id
}

# Certificate Validation for Docs
resource "aws_acm_certificate_validation" "docs" {
  count                   = var.enable_docs ? 1 : 0
  provider                = aws.us_east_1
  certificate_arn         = aws_acm_certificate.docs[0].arn
  validation_record_fqdns = [for record in aws_route53_record.docs_cert_validation : record.fqdn]
}

# Route 53 Record for Docs (CloudFront)
# When enable_docs is true, CloudFront domain is always available from the docs module
resource "aws_route53_record" "docs" {
  count   = var.enable_docs ? 1 : 0
  zone_id = data.aws_route53_zone.main.zone_id
  name    = local.docs_domain
  type    = "A"

  alias {
    name                   = var.docs_cloudfront_domain_name
    zone_id                = var.docs_cloudfront_zone_id
    evaluate_target_health = false
  }

  depends_on = [aws_acm_certificate_validation.docs]
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

# Docs outputs
output "docs_domain" {
  value = var.enable_docs ? local.docs_domain : ""
}

output "docs_certificate_arn" {
  value = var.enable_docs ? aws_acm_certificate_validation.docs[0].certificate_arn : ""
}

# =============================================================================
# Marketing Site (a13e.com - root domain)
# =============================================================================

# ACM Certificate for Marketing CloudFront (must be in us-east-1)
# Includes both root domain and www subdomain
resource "aws_acm_certificate" "marketing" {
  count                     = var.enable_marketing ? 1 : 0
  provider                  = aws.us_east_1
  domain_name               = var.domain_name
  subject_alternative_names = ["www.${var.domain_name}"]
  validation_method         = "DNS"

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Name        = "a13e-${var.environment}-marketing-cert"
    Environment = var.environment
  }
}

# DNS Validation Records for Marketing cert
resource "aws_route53_record" "marketing_cert_validation" {
  for_each = var.enable_marketing ? {
    for dvo in aws_acm_certificate.marketing[0].domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  } : {}

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = data.aws_route53_zone.main.zone_id
}

# Certificate Validation for Marketing
resource "aws_acm_certificate_validation" "marketing" {
  count                   = var.enable_marketing ? 1 : 0
  provider                = aws.us_east_1
  certificate_arn         = aws_acm_certificate.marketing[0].arn
  validation_record_fqdns = [for record in aws_route53_record.marketing_cert_validation : record.fqdn]
}

# Route 53 Record for Marketing - Root Domain (a13e.com)
resource "aws_route53_record" "marketing" {
  count   = var.enable_marketing && var.marketing_cloudfront_domain_name != "" ? 1 : 0
  zone_id = data.aws_route53_zone.main.zone_id
  name    = var.domain_name
  type    = "A"

  alias {
    name                   = var.marketing_cloudfront_domain_name
    zone_id                = var.marketing_cloudfront_zone_id
    evaluate_target_health = false
  }

  depends_on = [aws_acm_certificate_validation.marketing]
}

# Route 53 Record for Marketing - WWW subdomain (www.a13e.com)
resource "aws_route53_record" "marketing_www" {
  count   = var.enable_marketing && var.marketing_cloudfront_domain_name != "" ? 1 : 0
  zone_id = data.aws_route53_zone.main.zone_id
  name    = "www.${var.domain_name}"
  type    = "A"

  alias {
    name                   = var.marketing_cloudfront_domain_name
    zone_id                = var.marketing_cloudfront_zone_id
    evaluate_target_health = false
  }

  depends_on = [aws_acm_certificate_validation.marketing]
}

# Marketing outputs
output "marketing_domain" {
  value = var.enable_marketing ? var.domain_name : ""
}

output "marketing_certificate_arn" {
  value = var.enable_marketing ? aws_acm_certificate_validation.marketing[0].certificate_arn : ""
}
