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

variable "allowed_ips" {
  type        = list(string)
  description = "List of IP addresses (CIDR notation) allowed to access the site. Empty list allows all traffic."
  default     = []
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

  // Build Content Security Policy - STRICT
  // All JavaScript is bundled via Vite - no external CDNs needed
  // Payment: Uses Stripe Checkout redirect (not embedded Stripe.js)
  // Fonts: System fonts only (Inter with system-ui fallbacks)
  // SECURITY NOTE: 'unsafe-inline' for style-src is required for:
  // - Tailwind CSS dynamically generated classes
  // - React inline styles
  const csp = [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "connect-src 'self' https://${var.api_domain}",
    "font-src 'self'",
    "frame-src 'none'",
    "object-src 'none'",
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

  // X-Robots-Tag: Block AI training crawlers while allowing search indexing
  // This supplements robots.txt with HTTP header enforcement
  headers['x-robots-tag'] = [
    { key: 'X-Robots-Tag', value: 'noai, noimageai' },
    { key: 'X-Robots-Tag', value: 'GPTBot: noindex, nofollow' },
    { key: 'X-Robots-Tag', value: 'ChatGPT-User: noindex, nofollow' },
    { key: 'X-Robots-Tag', value: 'Google-Extended: noindex, nofollow' },
    { key: 'X-Robots-Tag', value: 'CCBot: noindex, nofollow' },
    { key: 'X-Robots-Tag', value: 'anthropic-ai: noindex, nofollow' },
    { key: 'X-Robots-Tag', value: 'Bytespider: noindex, nofollow' },
    { key: 'X-Robots-Tag', value: 'PerplexityBot: noindex, nofollow' },
    { key: 'X-Robots-Tag', value: 'Amazonbot: noindex, nofollow' },
    { key: 'X-Robots-Tag', value: 'FacebookBot: noindex, nofollow' },
    { key: 'X-Robots-Tag', value: 'cohere-ai: noindex, nofollow' }
  ];

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
# WAF IP Allowlist (for restricting access to specific IPs)
# ============================================================================

# IP Set for allowed addresses (only created when IPs are specified)
resource "aws_wafv2_ip_set" "allowed_ips" {
  count              = length(var.allowed_ips) > 0 ? 1 : 0
  provider           = aws.us_east_1
  name               = "a13e-${var.environment}-allowed-ips"
  description        = "IP addresses allowed to access ${var.environment}"
  scope              = "CLOUDFRONT"
  ip_address_version = "IPV4"
  addresses          = var.allowed_ips

  tags = {
    Name        = "a13e-${var.environment}-allowed-ips"
    Environment = var.environment
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

  # Custom response for blocked requests - "Coming Soon" page
  dynamic "custom_response_body" {
    for_each = length(var.allowed_ips) > 0 ? [1] : []
    content {
      key          = "coming-soon"
      content_type = "TEXT_HTML"
      content      = <<-HTML
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>A13E - Cloud Security Detection Coverage</title>
  <style>
    *{margin:0;padding:0;box-sizing:border-box}
    body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0f172a;min-height:100vh;display:flex;align-items:center;justify-content:center;color:#e2e8f0;overflow:hidden}
    .bg{position:fixed;inset:0;background:radial-gradient(ellipse at 50% 0%,rgba(59,130,246,0.15) 0%,transparent 50%),radial-gradient(ellipse at 80% 80%,rgba(139,92,246,0.1) 0%,transparent 40%)}
    .c{position:relative;text-align:center;padding:2rem;max-width:540px}
    .icon{width:72px;height:72px;margin:0 auto 1.5rem;position:relative}
    .icon svg{width:100%;height:100%}
    .icon::before{content:'';position:absolute;inset:-8px;background:linear-gradient(135deg,rgba(59,130,246,0.2),rgba(139,92,246,0.2));border-radius:50%;filter:blur(20px)}
    .logo{font-size:2.5rem;font-weight:800;background:linear-gradient(135deg,#3b82f6 0%,#06b6d4 50%,#8b5cf6 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;margin-bottom:0.5rem;letter-spacing:-0.02em}
    .tag{font-size:0.75rem;text-transform:uppercase;letter-spacing:0.1em;color:#64748b;margin-bottom:2rem}
    h1{font-size:2.25rem;font-weight:700;margin-bottom:1rem;color:#f8fafc;line-height:1.2}
    h1 span{background:linear-gradient(135deg,#3b82f6,#8b5cf6);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
    p{font-size:1rem;color:#94a3b8;line-height:1.7;margin-bottom:2rem}
    .chips{display:flex;gap:0.5rem;justify-content:center;flex-wrap:wrap;margin-bottom:2rem}
    .chip{padding:0.375rem 0.75rem;background:rgba(30,41,59,0.8);border:1px solid #334155;border-radius:6px;font-size:0.75rem;color:#cbd5e1;display:flex;align-items:center;gap:0.375rem}
    .chip svg{width:14px;height:14px}
    .form{display:flex;gap:0.5rem;max-width:360px;margin:0 auto 1.5rem}
    .form input{flex:1;padding:0.75rem 1rem;background:#1e293b;border:1px solid #334155;border-radius:8px;color:#f1f5f9;font-size:0.875rem}
    .form input::placeholder{color:#64748b}
    .form input:focus{outline:none;border-color:#3b82f6;box-shadow:0 0 0 3px rgba(59,130,246,0.1)}
    .form button{padding:0.75rem 1.25rem;background:linear-gradient(135deg,#3b82f6,#6366f1);border:none;border-radius:8px;color:#fff;font-weight:600;font-size:0.875rem;cursor:pointer;white-space:nowrap}
    .form button:hover{opacity:0.9}
    .badge{display:inline-flex;align-items:center;gap:0.5rem;padding:0.5rem 1rem;background:rgba(34,197,94,0.1);border:1px solid rgba(34,197,94,0.3);border-radius:9999px;font-size:0.8rem;color:#4ade80}
    .badge::before{content:'';width:6px;height:6px;background:#4ade80;border-radius:50%;animation:pulse 2s infinite}
    @keyframes pulse{0%%,100%%{opacity:1}50%%{opacity:0.5}}
  </style>
</head>
<body>
  <div class="bg"></div>
  <div class="c">
    <div class="icon">
      <svg viewBox="0 0 24 24" fill="none">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" stroke="url(#g)" stroke-width="1.5" fill="rgba(59,130,246,0.1)"/>
        <path d="M9 12l2 2 4-4" stroke="#22c55e" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
        <defs><linearGradient id="g" x1="4" y1="2" x2="20" y2="22"><stop stop-color="#3b82f6"/><stop offset="1" stop-color="#8b5cf6"/></linearGradient></defs>
      </svg>
    </div>
    <div class="logo">A13E</div>
    <div class="tag">Detection Coverage Validator</div>
    <h1>Know Your <span>Coverage Gaps</span></h1>
    <p>We're building something powerful for cloud security teams. Map your AWS and GCP detections to MITRE ATT&CK, identify coverage gaps, and get actionable remediation guidance.</p>
    <div class="chips">
      <span class="chip"><svg viewBox="0 0 24 24" fill="none" stroke="#f97316" stroke-width="2"><path d="M21 16V8a2 2 0 00-1-1.73l-7-4a2 2 0 00-2 0l-7 4A2 2 0 003 8v8a2 2 0 001 1.73l7 4a2 2 0 002 0l7-4A2 2 0 0021 16z"/></svg>AWS</span>
      <span class="chip"><svg viewBox="0 0 24 24" fill="none" stroke="#4285f4" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 2a10 10 0 0110 10"/></svg>GCP</span>
      <span class="chip"><svg viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="2"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg>MITRE ATT&CK</span>
    </div>
    <form class="form" onsubmit="return false">
      <input type="email" placeholder="Enter your email for updates" />
      <button type="submit">Notify Me</button>
    </form>
    <span class="badge">Private Beta</span>
  </div>
</body>
</html>
      HTML
    }
  }

  # Default action: block if IP restriction is enabled, allow otherwise
  default_action {
    dynamic "block" {
      for_each = length(var.allowed_ips) > 0 ? [1] : []
      content {
        custom_response {
          response_code            = 403
          custom_response_body_key = "coming-soon"
        }
      }
    }
    dynamic "allow" {
      for_each = length(var.allowed_ips) == 0 ? [1] : []
      content {}
    }
  }

  # Rule 0: Allow traffic from allowlisted IPs (highest priority, only when IPs specified)
  dynamic "rule" {
    for_each = length(var.allowed_ips) > 0 ? [1] : []
    content {
      name     = "AllowListedIPs"
      priority = 0

      action {
        allow {}
      }

      statement {
        ip_set_reference_statement {
          arn = aws_wafv2_ip_set.allowed_ips[0].arn
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "a13e-${var.environment}-allowed-ips"
        sampled_requests_enabled   = true
      }
    }
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

  # Rule 5: Anonymous IP List (Tor, VPNs, proxies - BLOCK for security)
  # Security: Block traffic from known anonymous proxies, Tor exit nodes, and VPNs
  # This prevents attackers from hiding their identity during attacks
  rule {
    name     = "AWSManagedRulesAnonymousIpList"
    priority = 5

    override_action {
      none {} # Use rule's default action (BLOCK)
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
