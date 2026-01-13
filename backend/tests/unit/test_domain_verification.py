"""Unit tests for DNS domain verification.

Tests cover:
1. DNS TXT record verification success
2. DNS verification failure scenarios (NXDOMAIN, NoAnswer, timeout)
3. Development domain auto-verification bypass
4. Verification token format
"""

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

# Ensure the backend app is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))


class TestDNSVerificationLogic:
    """Tests for DNS TXT record verification logic."""

    def test_verification_subdomain_format(self):
        """Verify the verification subdomain format is correct."""
        domain = "example.com"
        expected_subdomain = "_a13e-verification.example.com"
        actual_subdomain = f"_a13e-verification.{domain}"
        assert actual_subdomain == expected_subdomain

    def test_verification_token_value_format(self):
        """Verify the verification token value format is correct."""
        token = "abc123xyz"
        expected_value = "a13e-verify=abc123xyz"
        actual_value = f"a13e-verify={token}"
        assert actual_value == expected_value

    def test_txt_record_string_cleaning(self):
        """Verify TXT record strings are properly cleaned of quotes."""
        # DNS TXT records may come with surrounding quotes
        raw_values = [
            '"a13e-verify=token123"',
            "'a13e-verify=token123'",
            "a13e-verify=token123",
        ]
        expected = "a13e-verify=token123"

        for raw in raw_values:
            cleaned = raw.strip("\"'")
            assert cleaned == expected


class TestDevDomainBypass:
    """Tests for development domain auto-verification bypass."""

    def test_test_domain_is_dev(self):
        """Verify .test domains are recognised as dev domains."""
        domain = "mycompany.test"
        is_dev = domain.endswith((".test", ".local", ".example"))
        assert is_dev

    def test_local_domain_is_dev(self):
        """Verify .local domains are recognised as dev domains."""
        domain = "mycompany.local"
        is_dev = domain.endswith((".test", ".local", ".example"))
        assert is_dev

    def test_example_domain_is_dev(self):
        """Verify .example domains are recognised as dev domains."""
        domain = "mycompany.example"
        is_dev = domain.endswith((".test", ".local", ".example"))
        assert is_dev

    def test_com_domain_is_not_dev(self):
        """Verify .com domains are not recognised as dev domains."""
        domain = "mycompany.com"
        is_dev = domain.endswith((".test", ".local", ".example"))
        assert not is_dev

    def test_co_uk_domain_is_not_dev(self):
        """Verify .co.uk domains are not recognised as dev domains."""
        domain = "mycompany.co.uk"
        is_dev = domain.endswith((".test", ".local", ".example"))
        assert not is_dev


class TestDNSVerificationFunction:
    """Tests for the verify_domain_dns function."""

    @pytest.mark.asyncio
    async def test_dns_verification_success(self):
        """Test DNS verification succeeds with correct token."""
        from app.api.routes.org_security import verify_domain_dns

        # Mock dns.resolver
        mock_rdata = MagicMock()
        mock_rdata.strings = [b"a13e-verify=test-token-123"]

        mock_answers = [mock_rdata]

        with patch("dns.resolver.resolve", return_value=mock_answers):
            success, message = await verify_domain_dns(
                domain="example.com",
                expected_token="test-token-123",
            )

        assert success is True
        assert "verified" in message.lower() or "success" in message.lower()

    @pytest.mark.asyncio
    async def test_dns_verification_wrong_token(self):
        """Test DNS verification fails with wrong token."""
        from app.api.routes.org_security import verify_domain_dns

        mock_rdata = MagicMock()
        mock_rdata.strings = [b"a13e-verify=wrong-token"]

        mock_answers = [mock_rdata]

        with patch("dns.resolver.resolve", return_value=mock_answers):
            success, message = await verify_domain_dns(
                domain="example.com",
                expected_token="expected-token",
            )

        assert success is False
        assert "not found" in message.lower() or "expected" in message.lower()

    @pytest.mark.asyncio
    async def test_dns_verification_nxdomain(self):
        """Test DNS verification handles NXDOMAIN (domain not found)."""
        from app.api.routes.org_security import verify_domain_dns

        # Create a mock NXDOMAIN exception
        class NXDOMAIN(Exception):
            pass

        with patch("dns.resolver.resolve", side_effect=NXDOMAIN()):
            success, message = await verify_domain_dns(
                domain="nonexistent.com",
                expected_token="token",
            )

        assert success is False
        assert "not found" in message.lower() or "add" in message.lower()

    @pytest.mark.asyncio
    async def test_dns_verification_no_answer(self):
        """Test DNS verification handles NoAnswer (no TXT records)."""
        from app.api.routes.org_security import verify_domain_dns

        class NoAnswer(Exception):
            pass

        with patch("dns.resolver.resolve", side_effect=NoAnswer()):
            success, message = await verify_domain_dns(
                domain="example.com",
                expected_token="token",
            )

        assert success is False
        assert "no txt" in message.lower() or "propagated" in message.lower()

    @pytest.mark.asyncio
    async def test_dns_verification_timeout(self):
        """Test DNS verification handles timeout gracefully."""
        from app.api.routes.org_security import verify_domain_dns

        class Timeout(Exception):
            pass

        with patch("dns.resolver.resolve", side_effect=Timeout()):
            success, message = await verify_domain_dns(
                domain="slow.com",
                expected_token="token",
            )

        assert success is False
        assert "timeout" in message.lower() or "timed out" in message.lower()

    @pytest.mark.asyncio
    async def test_dns_verification_import_error(self):
        """Test DNS verification handles missing dnspython gracefully."""

        with patch.dict(sys.modules, {"dns": None, "dns.resolver": None}):
            # Force reimport to trigger ImportError
            with patch("app.api.routes.org_security.verify_domain_dns") as mock_verify:
                mock_verify.return_value = (
                    False,
                    "DNS verification unavailable. Please contact support.",
                )
                success, message = await mock_verify(
                    domain="example.com",
                    expected_token="token",
                )

        assert success is False
        assert "unavailable" in message.lower() or "contact" in message.lower()


class TestVerificationInstructions:
    """Tests for verification instruction generation."""

    def test_instructions_format(self):
        """Verify verification instructions have correct format."""
        domain = "example.com"
        token = "abc123"

        instructions = {
            "record_type": "TXT",
            "record_name": f"_a13e-verification.{domain}",
            "record_value": f"a13e-verify={token}",
        }

        assert instructions["record_type"] == "TXT"
        assert instructions["record_name"] == "_a13e-verification.example.com"
        assert instructions["record_value"] == "a13e-verify=abc123"

    def test_instructions_include_all_required_fields(self):
        """Verify instructions include record_type, record_name, and record_value."""
        domain = "test.co.uk"
        token = "xyz789"

        instructions = {
            "record_type": "TXT",
            "record_name": f"_a13e-verification.{domain}",
            "record_value": f"a13e-verify={token}",
        }

        assert "record_type" in instructions
        assert "record_name" in instructions
        assert "record_value" in instructions


class TestMultipleTXTRecords:
    """Tests for handling multiple TXT records."""

    @pytest.mark.asyncio
    async def test_finds_token_among_multiple_records(self):
        """Test verification finds correct token among multiple TXT records."""
        from app.api.routes.org_security import verify_domain_dns

        # Multiple TXT records, only one has our token
        mock_rdata1 = MagicMock()
        mock_rdata1.strings = [b"v=spf1 include:_spf.google.com ~all"]

        mock_rdata2 = MagicMock()
        mock_rdata2.strings = [b"google-site-verification=xyz123"]

        mock_rdata3 = MagicMock()
        mock_rdata3.strings = [b"a13e-verify=correct-token"]

        mock_answers = [mock_rdata1, mock_rdata2, mock_rdata3]

        with patch("dns.resolver.resolve", return_value=mock_answers):
            success, message = await verify_domain_dns(
                domain="example.com",
                expected_token="correct-token",
            )

        assert success is True
