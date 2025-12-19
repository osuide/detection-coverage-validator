"""Email service using AWS SES."""

import os
from typing import Optional
import boto3
from botocore.exceptions import ClientError
import structlog

from app.core.config import get_settings

logger = structlog.get_logger()
settings = get_settings()

# Email templates
PASSWORD_RESET_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reset Your Password</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%); color: white; padding: 30px; text-align: center; border-radius: 8px 8px 0 0; }}
        .content {{ background: #ffffff; padding: 30px; border: 1px solid #e5e7eb; border-top: none; border-radius: 0 0 8px 8px; }}
        .button {{ display: inline-block; background: #6366f1; color: white; padding: 14px 28px; text-decoration: none; border-radius: 6px; font-weight: 600; margin: 20px 0; }}
        .button:hover {{ background: #4f46e5; }}
        .footer {{ text-align: center; margin-top: 30px; color: #6b7280; font-size: 14px; }}
        .warning {{ background: #fef3c7; border: 1px solid #f59e0b; padding: 12px; border-radius: 6px; margin: 20px 0; font-size: 14px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Password Reset Request</h1>
    </div>
    <div class="content">
        <p>Hi,</p>
        <p>We received a request to reset your password for your A13E Detection Coverage account. Click the button below to set a new password:</p>

        <p style="text-align: center;">
            <a href="{reset_link}" class="button">Reset Password</a>
        </p>

        <div class="warning">
            <strong>This link expires in 24 hours.</strong> If you didn't request this password reset, you can safely ignore this email.
        </div>

        <p>If the button doesn't work, copy and paste this link into your browser:</p>
        <p style="word-break: break-all; color: #6366f1;">{reset_link}</p>
    </div>
    <div class="footer">
        <p>A13E Detection Coverage Validator</p>
        <p>This is an automated message. Please do not reply.</p>
    </div>
</body>
</html>
"""

TEAM_INVITE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>You've Been Invited</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%); color: white; padding: 30px; text-align: center; border-radius: 8px 8px 0 0; }}
        .content {{ background: #ffffff; padding: 30px; border: 1px solid #e5e7eb; border-top: none; border-radius: 0 0 8px 8px; }}
        .button {{ display: inline-block; background: #6366f1; color: white; padding: 14px 28px; text-decoration: none; border-radius: 6px; font-weight: 600; margin: 20px 0; }}
        .button:hover {{ background: #4f46e5; }}
        .footer {{ text-align: center; margin-top: 30px; color: #6b7280; font-size: 14px; }}
        .org-name {{ font-size: 18px; font-weight: 600; color: #6366f1; }}
        .role-badge {{ display: inline-block; background: #e0e7ff; color: #4338ca; padding: 4px 12px; border-radius: 20px; font-size: 14px; font-weight: 500; }}
        .message-box {{ background: #f3f4f6; padding: 15px; border-radius: 6px; margin: 20px 0; font-style: italic; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>You're Invited!</h1>
    </div>
    <div class="content">
        <p>Hi,</p>
        <p>You've been invited to join <span class="org-name">{org_name}</span> on A13E Detection Coverage Validator.</p>

        <p>Your role: <span class="role-badge">{role}</span></p>

        {message_section}

        <p style="text-align: center;">
            <a href="{invite_link}" class="button">Accept Invitation</a>
        </p>

        <p><strong>This invitation expires in 7 days.</strong></p>

        <p>If the button doesn't work, copy and paste this link into your browser:</p>
        <p style="word-break: break-all; color: #6366f1;">{invite_link}</p>
    </div>
    <div class="footer">
        <p>A13E Detection Coverage Validator</p>
        <p>If you weren't expecting this invitation, you can safely ignore this email.</p>
    </div>
</body>
</html>
"""


class EmailService:
    """AWS SES Email Service."""

    def __init__(self):
        self.logger = logger.bind(service="EmailService")
        self._client = None
        self.from_email = os.environ.get("SES_FROM_EMAIL", "noreply@a13e.com")
        self.app_url = os.environ.get("APP_URL", "https://staging.a13e.com")
        self.enabled = os.environ.get("SES_ENABLED", "true").lower() == "true"

    @property
    def client(self):
        """Lazy-load SES client."""
        if self._client is None:
            region = os.environ.get("AWS_REGION", "us-east-1")
            self._client = boto3.client("ses", region_name=region)
        return self._client

    def _send_email(
        self,
        to_email: str,
        subject: str,
        html_body: str,
        text_body: Optional[str] = None,
    ) -> bool:
        """Send an email via AWS SES.

        Returns True if successful, False otherwise.
        """
        if not self.enabled:
            self.logger.info(
                "email_skipped",
                reason="SES disabled",
                to=to_email,
                subject=subject,
            )
            return True

        if text_body is None:
            # Generate plain text from HTML (basic strip)
            import re
            text_body = re.sub(r'<[^>]+>', '', html_body)
            text_body = re.sub(r'\s+', ' ', text_body).strip()

        try:
            response = self.client.send_email(
                Source=self.from_email,
                Destination={"ToAddresses": [to_email]},
                Message={
                    "Subject": {"Data": subject, "Charset": "UTF-8"},
                    "Body": {
                        "Text": {"Data": text_body, "Charset": "UTF-8"},
                        "Html": {"Data": html_body, "Charset": "UTF-8"},
                    },
                },
            )
            self.logger.info(
                "email_sent",
                to=to_email,
                subject=subject,
                message_id=response.get("MessageId"),
            )
            return True
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            error_message = e.response.get("Error", {}).get("Message", str(e))
            self.logger.error(
                "email_failed",
                to=to_email,
                subject=subject,
                error_code=error_code,
                error=error_message,
            )
            return False
        except Exception as e:
            self.logger.error(
                "email_failed",
                to=to_email,
                subject=subject,
                error=str(e),
            )
            return False

    def send_password_reset_email(self, to_email: str, reset_token: str) -> bool:
        """Send password reset email.

        Args:
            to_email: Recipient email address
            reset_token: The raw (unhashed) reset token

        Returns:
            True if email was sent successfully
        """
        reset_link = f"{self.app_url}/reset-password?token={reset_token}"

        html_body = PASSWORD_RESET_TEMPLATE.format(reset_link=reset_link)

        self.logger.info(
            "sending_password_reset",
            to=to_email,
            reset_link=reset_link[:50] + "...",
        )

        return self._send_email(
            to_email=to_email,
            subject="Reset Your A13E Password",
            html_body=html_body,
        )

    def send_team_invite_email(
        self,
        to_email: str,
        invite_token: str,
        org_name: str,
        role: str,
        message: Optional[str] = None,
        inviter_name: Optional[str] = None,
    ) -> bool:
        """Send team invitation email.

        Args:
            to_email: Recipient email address
            invite_token: The raw (unhashed) invite token
            org_name: Name of the organization
            role: Role being assigned (e.g., "Admin", "Member")
            message: Optional personal message from inviter
            inviter_name: Optional name of person who sent the invite

        Returns:
            True if email was sent successfully
        """
        invite_link = f"{self.app_url}/invites/accept?token={invite_token}"

        # Build message section
        if message:
            message_section = f'<div class="message-box">"{message}"</div>'
            if inviter_name:
                message_section = f'<div class="message-box">"{message}"<br><br>— {inviter_name}</div>'
        else:
            message_section = ""

        html_body = TEAM_INVITE_TEMPLATE.format(
            org_name=org_name,
            role=role.title(),
            invite_link=invite_link,
            message_section=message_section,
        )

        self.logger.info(
            "sending_team_invite",
            to=to_email,
            org=org_name,
            role=role,
        )

        return self._send_email(
            to_email=to_email,
            subject=f"You've been invited to join {org_name} on A13E",
            html_body=html_body,
        )


# Singleton instance
_email_service: Optional[EmailService] = None


def get_email_service() -> EmailService:
    """Get the email service singleton."""
    global _email_service
    if _email_service is None:
        _email_service = EmailService()
    return _email_service
