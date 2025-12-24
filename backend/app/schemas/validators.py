"""Custom Pydantic validators for fraud prevention."""

from typing import Annotated

from pydantic import AfterValidator, EmailStr

from app.services.email_quality_service import get_email_quality_service


def validate_email_quality_sync(email: str) -> str:
    """Synchronous wrapper for email quality validation.

    Performs disposable domain check only (fast, no I/O).
    For full async validation with MX check, use the service directly.

    Args:
        email: Email address to validate

    Returns:
        The email if valid

    Raises:
        ValueError: If email is from a disposable domain
    """
    service = get_email_quality_service()

    # Sync check - disposable domain only (fast, no network I/O)
    try:
        domain = email.lower().rsplit("@", 1)[1]
    except (ValueError, IndexError):
        raise ValueError("Invalid email format")

    if service.is_disposable_domain(domain):
        raise ValueError(
            "Please use a permanent email address. "
            "Disposable email addresses are not allowed."
        )

    return email


# Annotated type for validated email - blocks disposable domains
ValidatedEmail = Annotated[EmailStr, AfterValidator(validate_email_quality_sync)]
