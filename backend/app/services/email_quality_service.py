"""Email quality validation service for fraud prevention.

Blocks disposable/temporary email addresses to prevent abuse of the free tier.
"""

import asyncio
import re
from typing import Optional, Set, Tuple

import structlog

logger = structlog.get_logger()

# Comprehensive blocklist of disposable email domains
# Source: https://github.com/disposable-email-domains/disposable-email-domains
DISPOSABLE_DOMAINS: Set[str] = {
    # Top disposable domains (commonly used for abuse)
    "tempmail.com",
    "temp-mail.org",
    "guerrillamail.com",
    "guerrillamail.org",
    "mailinator.com",
    "maildrop.cc",
    "10minutemail.com",
    "10minutemail.net",
    "throwaway.email",
    "throwawaymail.com",
    "dispostable.com",
    "fakeinbox.com",
    "mailnesia.com",
    "sharklasers.com",
    "yopmail.com",
    "yopmail.fr",
    "trashmail.com",
    "trashmail.net",
    "getnada.com",
    "nada.email",
    "tempinbox.com",
    "tempr.email",
    "discard.email",
    "discardmail.com",
    "disposableemailaddresses.com",
    "emailondeck.com",
    "getairmail.com",
    "mohmal.com",
    "spambox.us",
    "spamgourmet.com",
    "burnermail.io",
    "mytemp.email",
    "tempail.com",
    "tmpmail.org",
    "tmpmail.net",
    "fakemailgenerator.com",
    "emailfake.com",
    "fakemail.net",
    "guerrillamailblock.com",
    "mintemail.com",
    "mt2015.com",
    "mailsac.com",
    "mailslurp.com",
    "emailna.co",
    "inboxkitten.com",
    "mailpoof.com",
    "tempmailaddress.com",
    "tempmailin.com",
    "dropmail.me",
    "crazymailing.com",
    "haltospam.com",
    "harakirimail.com",
    # Extended list
    "1secmail.com",
    "1secmail.net",
    "1secmail.org",
    "5mail.cf",
    "5mail.ga",
    "5mail.gq",
    "5mail.ml",
    "byom.de",
    "chacuo.net",
    "cko.kr",
    "cool.fr.nf",
    "courriel.fr.nf",
    "disbox.net",
    "disbox.org",
    "einrot.com",
    "emkei.cz",
    "fleckens.hu",
    "generator.email",
    "getmails.eu",
    "gg.gg",
    "gishpuppy.com",
    "grr.la",
    "guerrillamail.biz",
    "guerrillamail.de",
    "guerrillamail.info",
    "guerrillamail.net",
    "hmamail.com",
    "imgof.com",
    "imgv.de",
    "jetable.fr.nf",
    "kasmail.com",
    "keemail.me",
    "mailcatch.com",
    "mailchop.com",
    "mailexpire.com",
    "mailfree.ga",
    "mailfree.gq",
    "mailfree.ml",
    "mailhub.pw",
    "mailimate.com",
    "mailsiphon.com",
    "mailtemp.info",
    "meltmail.com",
    "moakt.cc",
    "moakt.co",
    "moakt.ws",
    "mvrht.net",
    "notmailinator.com",
    "owlpic.com",
    "pokemail.net",
    "proxymail.eu",
    "rcpt.at",
    "rejectmail.com",
    "rtrtr.com",
    "s0ny.net",
    "spamavert.com",
    "spambog.com",
    "spambog.de",
    "spambog.ru",
    "spamex.com",
    "spamherelots.com",
    "spamtroll.net",
    "superrito.com",
    "sute.jp",
    "techemail.com",
    "tempemail.biz",
    "tempemail.co.za",
    "tempemail.com",
    "tempemail.net",
    "temporaryemail.net",
    "temporaryforwarding.com",
    "temporaryinbox.com",
    "thankyou2010.com",
    "thisisnotmyrealemail.com",
    "throwawayemailaddress.com",
    "tmail.ws",
    "tmpjr.me",
    "trash-mail.at",
    "trash-mail.com",
    "trash-mail.de",
    "trash2009.com",
    "trashdevil.com",
    "trashemail.de",
    "trashymail.com",
    "trashymail.net",
    "wegwerfmail.de",
    "wegwerfmail.net",
    "wegwerfmail.org",
    "wetrash.com",
    "wh4f.org",
    "whopy.com",
    "willhackforfood.biz",
    "willselfdestruct.com",
    "wuzupmail.net",
    "xagloo.co",
    "xmaily.com",
    "yep.it",
    "yogamaven.com",
    "zetmail.com",
    "zoemail.net",
    "zoemail.org",
}

# Patterns for disposable domain detection
DISPOSABLE_PATTERNS = [
    r"^temp[.-]?mail",
    r"^throw[.-]?away",
    r"^trash[.-]?mail",
    r"^fake[.-]?mail",
    r"^spam[.-]?",
    r"^disposable",
    r"^guerrilla",
    r"^mailinator",
    r"10minute",
    r"burner",
]


class EmailQualityService:
    """Service for validating email quality and blocking disposable addresses."""

    def __init__(self) -> None:
        self._compiled_patterns = [re.compile(p, re.I) for p in DISPOSABLE_PATTERNS]

    def is_disposable_domain(self, domain: str) -> bool:
        """Check if domain is a known disposable email provider.

        Args:
            domain: Email domain to check

        Returns:
            True if domain is disposable, False otherwise
        """
        domain = domain.lower().strip()

        # Direct blocklist match
        if domain in DISPOSABLE_DOMAINS:
            return True

        # Pattern matching for variations
        for pattern in self._compiled_patterns:
            if pattern.search(domain):
                return True

        return False

    async def validate_mx_records(
        self, domain: str, timeout: float = 5.0
    ) -> Tuple[bool, Optional[str]]:
        """Verify domain has valid MX records (can receive email).

        Args:
            domain: Email domain to validate
            timeout: Maximum time to wait for DNS lookup

        Returns:
            (has_mx, error_message)
        """
        try:
            # Import here to make dnspython an optional dependency
            from dns import resolver

            loop = asyncio.get_event_loop()

            # Run DNS lookup in executor with timeout to avoid blocking/hanging
            mx_records = await asyncio.wait_for(
                loop.run_in_executor(
                    None, lambda: resolver.resolve(domain, "MX", lifetime=timeout)
                ),
                timeout=timeout + 1,  # Extra second for executor overhead
            )
            if mx_records:
                return True, None
            return False, "Domain has no MX records"

        except ImportError:
            # dnspython not installed - skip MX validation
            logger.warning("dnspython_not_installed_skipping_mx_check")
            return True, None
        except asyncio.TimeoutError:
            logger.warning("mx_lookup_timeout", domain=domain)
            # Don't block on timeout - may be slow DNS
            return True, None
        except Exception as e:
            # Handle DNS exceptions by checking exception class name
            error_name = type(e).__name__
            if error_name == "NXDOMAIN":
                return False, "Domain does not exist"
            if error_name == "NoAnswer":
                return False, "Domain has no MX records"
            if error_name == "Timeout":
                logger.warning("mx_lookup_dns_timeout", domain=domain)
                return True, None

            logger.warning("mx_lookup_failed", domain=domain, error=str(e))
            # Don't block on DNS failures - may be temporary
            return True, None

    async def validate_email_quality(
        self,
        email: str,
        check_mx: bool = True,
    ) -> Tuple[bool, Optional[str]]:
        """Comprehensive email quality validation.

        Checks:
        1. Disposable domain blocklist
        2. Disposable domain patterns
        3. Valid MX records (optional)

        Args:
            email: Email address to validate
            check_mx: Whether to check MX records

        Returns:
            (is_valid, error_message)
        """
        try:
            local, domain = email.lower().rsplit("@", 1)
        except ValueError:
            return False, "Invalid email format"

        # Check disposable domains
        if self.is_disposable_domain(domain):
            logger.warning(
                "disposable_email_blocked",
                domain=domain,
                email_hash=hash(email),  # Don't log full email
            )
            return (
                False,
                "Please use a permanent email address. "
                "Disposable email addresses are not allowed.",
            )

        # Check MX records
        if check_mx:
            has_mx, mx_error = await self.validate_mx_records(domain)
            if not has_mx:
                logger.warning(
                    "email_mx_validation_failed",
                    domain=domain,
                    error=mx_error,
                )
                return False, f"Unable to verify email domain: {mx_error}"

        return True, None


# Singleton instance
_email_quality_service: Optional[EmailQualityService] = None


def get_email_quality_service() -> EmailQualityService:
    """Get singleton email quality service."""
    global _email_quality_service
    if _email_quality_service is None:
        _email_quality_service = EmailQualityService()
    return _email_quality_service
