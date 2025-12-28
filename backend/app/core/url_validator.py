"""URL validation to prevent SSRF attacks.

Validates outbound URLs to prevent Server-Side Request Forgery (SSRF) by:
1. Enforcing HTTPS-only scheme
2. Blocking private/internal IP ranges (RFC 1918, link-local, loopback, metadata)
3. Resolving hostnames and checking all resolved IPs
4. Optionally enforcing an allowlist of known webhook providers
"""

import ipaddress
import socket
from typing import Optional
from urllib.parse import urlparse

import structlog

logger = structlog.get_logger()

# Blocked IP ranges (RFC 1918, link-local, loopback, metadata)
BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local + AWS metadata
    ipaddress.ip_network("::1/128"),  # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),  # IPv6 private
    ipaddress.ip_network("fe80::/10"),  # IPv6 link-local
]

# Allowed URL schemes
ALLOWED_SCHEMES = {"https"}

# Allowlist for known webhook providers
ALLOWED_WEBHOOK_HOSTS = {
    "hooks.slack.com",
    "discord.com",
    "discordapp.com",
    "webhook.site",  # For testing
    "api.pagerduty.com",
    "events.pagerduty.com",
    "api.opsgenie.com",
    # Add other known webhook providers as needed
}


class SSRFError(ValueError):
    """SSRF validation error."""

    pass


def validate_webhook_url(url: str, require_allowlist: bool = False) -> str:
    """Validate URL is safe for outbound webhook requests.

    Args:
        url: The URL to validate
        require_allowlist: If True, only allow known webhook providers

    Returns:
        The validated URL

    Raises:
        SSRFError: If URL is potentially unsafe
    """
    if not url:
        raise SSRFError("URL is required")

    try:
        parsed = urlparse(url)
    except Exception as e:
        raise SSRFError(f"Invalid URL format: {e}")

    # Validate scheme
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise SSRFError(f"URL scheme must be HTTPS, got: {parsed.scheme}")

    # Validate host exists
    if not parsed.hostname:
        raise SSRFError("URL must include a hostname")

    hostname = parsed.hostname.lower()

    # Block obvious internal hostnames
    if hostname in ("localhost", "127.0.0.1", "::1"):
        raise SSRFError("Localhost addresses are not allowed for webhooks")

    # Check for AWS metadata service hostname
    if hostname == "metadata.google.internal":
        raise SSRFError("Cloud metadata service is not allowed for webhooks")

    # Optional: Check allowlist
    if require_allowlist:
        if hostname not in ALLOWED_WEBHOOK_HOSTS:
            raise SSRFError(
                f"Webhook host '{hostname}' not in allowed list. "
                "Contact support to add new webhook providers."
            )

    # Resolve hostname and check IP
    try:
        # Get all IP addresses for the hostname
        infos = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC)
        ips = {info[4][0] for info in infos}
    except socket.gaierror as e:
        raise SSRFError(f"Cannot resolve hostname: {e}")

    if not ips:
        raise SSRFError("Hostname resolved to no IP addresses")

    for ip_str in ips:
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue

        for network in BLOCKED_NETWORKS:
            if ip in network:
                logger.warning(
                    "ssrf_blocked",
                    url=url,
                    hostname=hostname,
                    blocked_ip=ip_str,
                    network=str(network),
                )
                raise SSRFError(
                    "URL resolves to blocked IP range. "
                    "Internal addresses are not allowed for webhooks."
                )

    return url


def is_url_safe(url: str, require_allowlist: bool = False) -> bool:
    """Check if a URL is safe without raising an exception.

    Args:
        url: The URL to check
        require_allowlist: If True, only allow known webhook providers

    Returns:
        True if the URL is safe, False otherwise
    """
    try:
        validate_webhook_url(url, require_allowlist=require_allowlist)
        return True
    except SSRFError:
        return False


def get_validation_error(url: str, require_allowlist: bool = False) -> Optional[str]:
    """Get the validation error message for a URL, if any.

    Args:
        url: The URL to check
        require_allowlist: If True, only allow known webhook providers

    Returns:
        Error message if URL is unsafe, None if URL is safe
    """
    try:
        validate_webhook_url(url, require_allowlist=require_allowlist)
        return None
    except SSRFError as e:
        return str(e)
