# AWS SES Email Configuration
# Note: SES requires domain verification and may need manual steps for production

variable "domain" {
  description = "Domain for SES email sending"
  type        = string
}

variable "environment" {
  description = "Environment name"
  type        = string
}

variable "tags" {
  description = "Tags to apply to resources"
  type        = map(string)
  default     = {}
}

# SES Domain Identity
resource "aws_ses_domain_identity" "main" {
  domain = var.domain
}

# SES Domain DKIM
resource "aws_ses_domain_dkim" "main" {
  domain = aws_ses_domain_identity.main.domain
}

# SES Domain Mail From
resource "aws_ses_domain_mail_from" "main" {
  domain           = aws_ses_domain_identity.main.domain
  mail_from_domain = "mail.${var.domain}"
}

# Configuration Set for tracking
resource "aws_ses_configuration_set" "main" {
  name = "${var.environment}-a13e-emails"

  reputation_metrics_enabled = true
  sending_enabled            = true

  delivery_options {
    tls_policy = "REQUIRE"
  }
}

# Email templates
resource "aws_ses_template" "password_reset" {
  name    = "${var.environment}-password-reset"
  subject = "Reset Your A13E Password"
  html    = <<-EOF
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Reset Your Password</title>
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%); color: white; padding: 30px; text-align: center; border-radius: 8px 8px 0 0;">
        <h1>Password Reset Request</h1>
    </div>
    <div style="background: #ffffff; padding: 30px; border: 1px solid #e5e7eb; border-top: none; border-radius: 0 0 8px 8px;">
        <p>Hi,</p>
        <p>We received a request to reset your password for your A13E Detection Coverage account.</p>
        <p style="text-align: center;">
            <a href="{{reset_link}}" style="display: inline-block; background: #6366f1; color: white; padding: 14px 28px; text-decoration: none; border-radius: 6px; font-weight: 600;">Reset Password</a>
        </p>
        <p><strong>This link expires in 24 hours.</strong></p>
    </div>
</body>
</html>
EOF
  text    = "Reset your password by visiting: {{reset_link}}\n\nThis link expires in 24 hours."
}

resource "aws_ses_template" "team_invite" {
  name    = "${var.environment}-team-invite"
  subject = "You've been invited to join {{org_name}} on A13E"
  html    = <<-EOF
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Team Invitation</title>
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%); color: white; padding: 30px; text-align: center; border-radius: 8px 8px 0 0;">
        <h1>You're Invited!</h1>
    </div>
    <div style="background: #ffffff; padding: 30px; border: 1px solid #e5e7eb; border-top: none; border-radius: 0 0 8px 8px;">
        <p>Hi,</p>
        <p>You've been invited to join <strong>{{org_name}}</strong> on A13E Detection Coverage Validator.</p>
        <p>Your role: <span style="background: #e0e7ff; color: #4338ca; padding: 4px 12px; border-radius: 20px;">{{role}}</span></p>
        <p style="text-align: center;">
            <a href="{{invite_link}}" style="display: inline-block; background: #6366f1; color: white; padding: 14px 28px; text-decoration: none; border-radius: 6px; font-weight: 600;">Accept Invitation</a>
        </p>
        <p><strong>This invitation expires in 7 days.</strong></p>
    </div>
</body>
</html>
EOF
  text    = "You've been invited to join {{org_name}} on A13E.\n\nAccept your invitation: {{invite_link}}\n\nThis invitation expires in 7 days."
}

# Outputs
output "domain_identity_arn" {
  description = "ARN of the SES domain identity"
  value       = aws_ses_domain_identity.main.arn
}

output "domain_verification_token" {
  description = "Token for domain verification (add as TXT record)"
  value       = aws_ses_domain_identity.main.verification_token
}

output "dkim_tokens" {
  description = "DKIM tokens for DNS (add as CNAME records)"
  value       = aws_ses_domain_dkim.main.dkim_tokens
}

output "mail_from_domain" {
  description = "Mail from domain"
  value       = aws_ses_domain_mail_from.main.mail_from_domain
}

output "configuration_set_name" {
  description = "Name of the SES configuration set"
  value       = aws_ses_configuration_set.main.name
}
